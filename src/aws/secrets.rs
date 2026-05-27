use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct SecretsManagerRow {
    pub region: String,
    pub name: String,
    pub arn: String,
    pub last_changed: String,
    pub last_accessed: String,
    pub kms_key_id: String,
    pub rotation_enabled: bool,
}

#[derive(Serialize, Clone)]
pub struct SsmParameterRow {
    pub region: String,
    pub name: String,
    pub r#type: String,
    pub last_modified: String,
    pub key_id: String,
    pub description: String,
}

#[derive(Serialize)]
struct CombinedSecrets {
    secretsmanager: Vec<SecretsManagerRow>,
    ssm_parameters: Vec<SsmParameterRow>,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[secrets]".cyan().bold());

    let regions = factory.regions.clone();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let factory = Arc::new(factory.clone());

    let mut handles = Vec::with_capacity(regions.len());
    for region in regions {
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let sm = list_secretsmanager(&factory, &region).await;
            let ssm = list_ssm(&factory, &region).await;
            (sm, ssm)
        }));
    }

    let mut sm_rows: Vec<SecretsManagerRow> = Vec::new();
    let mut ssm_rows: Vec<SsmParameterRow> = Vec::new();
    for h in handles {
        if let Ok((sm, ssm)) = h.await {
            sm_rows.extend(sm);
            ssm_rows.extend(ssm);
        }
    }

    if sm_rows.is_empty() && ssm_rows.is_empty() {
        println!("No secrets found (or insufficient permissions).");
        return Ok(());
    }

    // Combined display table (Region | Service | Name | Type | LastModified)
    let mut display: Vec<Vec<String>> = Vec::new();
    for r in &sm_rows {
        display.push(vec![
            r.region.clone(),
            "SecretsManager".to_string(),
            r.name.clone(),
            "-".to_string(),
            r.last_changed.clone(),
        ]);
    }
    for r in &ssm_rows {
        display.push(vec![
            r.region.clone(),
            "SSM".to_string(),
            r.name.clone(),
            r.r#type.clone(),
            r.last_modified.clone(),
        ]);
    }

    let headers = &["Region", "Service", "Name", "Type", "LastModified"];
    output.print_table(headers, &display);
    output.write_table("secrets", headers, &display)?;

    output.write_csv("secrets-secretsmanager", &sm_rows)?;
    output.write_csv("secrets-ssm", &ssm_rows)?;

    let combined = CombinedSecrets {
        secretsmanager: sm_rows.clone(),
        ssm_parameters: ssm_rows.clone(),
    };
    output.write_json("secrets", &combined)?;

    // Loot commands — pure metadata pull, never fetch the values automatically.
    let mut loot = String::new();
    loot.push_str("# Follow-up: actually retrieve secret values (review before running)\n\n");
    for r in &sm_rows {
        loot.push_str(&format!(
            "aws --profile {} --region {} secretsmanager get-secret-value --secret-id {}\n",
            factory.profile, r.region, r.arn
        ));
    }
    loot.push('\n');
    for r in &ssm_rows {
        let decrypt = if r.r#type == "SecureString" {
            " --with-decryption"
        } else {
            ""
        };
        loot.push_str(&format!(
            "aws --profile {} --region {} ssm get-parameter --name {}{}\n",
            factory.profile, r.region, r.name, decrypt
        ));
    }
    output.loot_commands("secrets-get-commands", &loot)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}

async fn list_secretsmanager(factory: &ClientFactory, region: &str) -> Vec<SecretsManagerRow> {
    let client = factory.secretsmanager(region);
    let mut out = Vec::new();
    let mut pages = client.list_secrets().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} list_secrets({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                break;
            }
        };
        for s in page.secret_list() {
            out.push(SecretsManagerRow {
                region: region.to_string(),
                name: s.name().unwrap_or_default().to_string(),
                arn: s.arn().unwrap_or_default().to_string(),
                last_changed: s
                    .last_changed_date()
                    .map(|d| d.secs().to_string())
                    .unwrap_or_default(),
                last_accessed: s
                    .last_accessed_date()
                    .map(|d| d.secs().to_string())
                    .unwrap_or_default(),
                kms_key_id: s.kms_key_id().unwrap_or_default().to_string(),
                rotation_enabled: s.rotation_enabled().unwrap_or(false),
            });
        }
    }
    out
}

async fn list_ssm(factory: &ClientFactory, region: &str) -> Vec<SsmParameterRow> {
    let client = factory.ssm(region);
    let mut out = Vec::new();
    let mut pages = client.describe_parameters().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} describe_parameters({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                break;
            }
        };
        for p in page.parameters() {
            out.push(SsmParameterRow {
                region: region.to_string(),
                name: p.name().unwrap_or_default().to_string(),
                r#type: p
                    .r#type()
                    .map(|t| t.as_str().to_string())
                    .unwrap_or_default(),
                last_modified: p
                    .last_modified_date()
                    .map(|d| d.secs().to_string())
                    .unwrap_or_default(),
                key_id: p.key_id().unwrap_or_default().to_string(),
                description: p.description().unwrap_or_default().to_string(),
            });
        }
    }
    out
}
