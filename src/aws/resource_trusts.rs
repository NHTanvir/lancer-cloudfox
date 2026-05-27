use anyhow::Result;
use aws_sdk_sqs::types::QueueAttributeName;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct ResourceTrustRow {
    #[serde(rename = "Region")]
    pub region: String,
    #[serde(rename = "Service")]
    pub service: String,
    #[serde(rename = "ResourceName")]
    pub resource_name: String,
    #[serde(rename = "TrustedEntity")]
    pub trusted_entity: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "External")]
    pub external: bool,
}

/// (loot_dir, file_name, body)
type LootEntry = (String, String, Vec<u8>);

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn account_from_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 5 && !parts[4].is_empty() {
        Some(parts[4].to_string())
    } else {
        None
    }
}

fn as_string_vec(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

fn is_external(value: &str, caller_account: &str) -> bool {
    if value == "*" {
        return true;
    }
    if let Some(acct) = account_from_arn(value) {
        return !caller_account.is_empty() && acct != caller_account;
    }
    if value.len() == 12 && value.chars().all(|c| c.is_ascii_digit()) {
        return !caller_account.is_empty() && value != caller_account;
    }
    false
}

fn process_policy(
    region: &str,
    service: &str,
    resource_name: &str,
    policy_json: &str,
    caller_account: &str,
    rows: &mut Vec<ResourceTrustRow>,
) {
    let v: Value = match serde_json::from_str(policy_json) {
        Ok(v) => v,
        Err(_) => return,
    };

    let stmts: Vec<Value> = match v.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Object(_)) => vec![v.get("Statement").unwrap().clone()],
        _ => return,
    };

    for stmt in &stmts {
        if stmt
            .get("Effect")
            .and_then(|x| x.as_str())
            .unwrap_or("Allow")
            != "Allow"
        {
            continue;
        }

        let actions = stmt
            .get("Action")
            .map(as_string_vec)
            .unwrap_or_default();
        let action_str = if actions.is_empty() {
            "*".to_string()
        } else {
            actions.join(",")
        };

        let principal = match stmt.get("Principal") {
            Some(p) => p.clone(),
            None => continue,
        };

        let mut entries: Vec<String> = Vec::new();
        match &principal {
            Value::String(s) => entries.push(s.clone()),
            Value::Object(map) => {
                for (_k, v) in map.iter() {
                    entries.extend(as_string_vec(v));
                }
            }
            _ => {}
        }

        for entry in entries {
            let external = is_external(&entry, caller_account);
            rows.push(ResourceTrustRow {
                region: region.to_string(),
                service: service.to_string(),
                resource_name: resource_name.to_string(),
                trusted_entity: entry,
                action: action_str.clone(),
                external,
            });
        }
    }
}

async fn scan_s3(
    factory: Arc<ClientFactory>,
    caller_account: Arc<String>,
) -> (Vec<ResourceTrustRow>, Vec<LootEntry>) {
    let client = factory.s3();
    let mut rows: Vec<ResourceTrustRow> = Vec::new();
    let mut loot: Vec<LootEntry> = Vec::new();

    let resp = match client.list_buckets().send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} s3 list_buckets failed: {}", "[-]".yellow(), e);
            return (rows, loot);
        }
    };

    for bucket in resp.buckets() {
        let name = match bucket.name() {
            Some(n) => n.to_string(),
            None => continue,
        };
        match client.get_bucket_policy().bucket(&name).send().await {
            Ok(p) => {
                if let Some(policy) = p.policy() {
                    loot.push((
                        "resource-policies".to_string(),
                        format!("s3-{}.json", sanitize(&name)),
                        policy.as_bytes().to_vec(),
                    ));
                    process_policy("global", "S3", &name, policy, &caller_account, &mut rows);
                }
            }
            Err(e) => {
                let s = e.to_string();
                if !s.contains("NoSuchBucketPolicy") && !s.contains("AccessDenied") {
                    eprintln!("{} s3 get_bucket_policy({}): {}", "[-]".yellow(), name, s);
                }
            }
        }
    }
    (rows, loot)
}

async fn scan_sns(
    factory: Arc<ClientFactory>,
    region: String,
    caller_account: Arc<String>,
) -> (Vec<ResourceTrustRow>, Vec<LootEntry>) {
    let client = factory.sns(&region);
    let mut rows: Vec<ResourceTrustRow> = Vec::new();
    let mut loot: Vec<LootEntry> = Vec::new();

    let mut paginator = client.list_topics().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} sns list_topics({}): {}", "[-]".yellow(), region, e);
                break;
            }
        };
        for topic in page.topics() {
            let arn = match topic.topic_arn() {
                Some(a) => a.to_string(),
                None => continue,
            };
            let short = arn.split(':').last().unwrap_or(&arn).to_string();
            match client.get_topic_attributes().topic_arn(&arn).send().await {
                Ok(resp) => {
                    if let Some(attrs) = resp.attributes() {
                        if let Some(policy) = attrs.get("Policy") {
                            loot.push((
                                "resource-policies".to_string(),
                                format!("sns-{}-{}.json", region, sanitize(&short)),
                                policy.as_bytes().to_vec(),
                            ));
                            process_policy(
                                &region,
                                "SNS",
                                &short,
                                policy,
                                &caller_account,
                                &mut rows,
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} sns get_topic_attributes({}): {}",
                        "[-]".yellow(),
                        short,
                        e
                    );
                }
            }
        }
    }
    (rows, loot)
}

async fn scan_sqs(
    factory: Arc<ClientFactory>,
    region: String,
    caller_account: Arc<String>,
) -> (Vec<ResourceTrustRow>, Vec<LootEntry>) {
    let client = factory.sqs(&region);
    let mut rows: Vec<ResourceTrustRow> = Vec::new();
    let mut loot: Vec<LootEntry> = Vec::new();

    let mut paginator = client.list_queues().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} sqs list_queues({}): {}", "[-]".yellow(), region, e);
                break;
            }
        };
        for url in page.queue_urls() {
            let short = url.split('/').last().unwrap_or(url).to_string();
            match client
                .get_queue_attributes()
                .queue_url(url)
                .attribute_names(QueueAttributeName::Policy)
                .send()
                .await
            {
                Ok(resp) => {
                    if let Some(attrs) = resp.attributes() {
                        if let Some(policy) = attrs.get(&QueueAttributeName::Policy) {
                            loot.push((
                                "resource-policies".to_string(),
                                format!("sqs-{}-{}.json", region, sanitize(&short)),
                                policy.as_bytes().to_vec(),
                            ));
                            process_policy(
                                &region,
                                "SQS",
                                &short,
                                policy,
                                &caller_account,
                                &mut rows,
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} sqs get_queue_attributes({}): {}",
                        "[-]".yellow(),
                        short,
                        e
                    );
                }
            }
        }
    }
    (rows, loot)
}

async fn scan_lambda(
    factory: Arc<ClientFactory>,
    region: String,
    caller_account: Arc<String>,
) -> (Vec<ResourceTrustRow>, Vec<LootEntry>) {
    let client = factory.lambda(&region);
    let mut rows: Vec<ResourceTrustRow> = Vec::new();
    let mut loot: Vec<LootEntry> = Vec::new();

    let mut paginator = client.list_functions().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} lambda list_functions({}): {}", "[-]".yellow(), region, e);
                break;
            }
        };
        for f in page.functions() {
            let name = match f.function_name() {
                Some(n) => n.to_string(),
                None => continue,
            };
            match client.get_policy().function_name(&name).send().await {
                Ok(p) => {
                    if let Some(policy) = p.policy() {
                        loot.push((
                            "resource-policies".to_string(),
                            format!("lambda-{}-{}.json", region, sanitize(&name)),
                            policy.as_bytes().to_vec(),
                        ));
                        process_policy(
                            &region,
                            "Lambda",
                            &name,
                            policy,
                            &caller_account,
                            &mut rows,
                        );
                    }
                }
                Err(e) => {
                    let s = e.to_string();
                    if s.contains("ResourceNotFound") {
                        continue;
                    }
                    eprintln!("{} lambda get_policy({}): {}", "[-]".yellow(), name, s);
                    continue;
                }
            }
        }
    }
    (rows, loot)
}

async fn scan_secrets(
    factory: Arc<ClientFactory>,
    region: String,
    caller_account: Arc<String>,
) -> (Vec<ResourceTrustRow>, Vec<LootEntry>) {
    let client = factory.secretsmanager(&region);
    let mut rows: Vec<ResourceTrustRow> = Vec::new();
    let mut loot: Vec<LootEntry> = Vec::new();

    let mut paginator = client.list_secrets().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} secretsmanager list_secrets({}): {}",
                    "[-]".yellow(),
                    region,
                    e
                );
                break;
            }
        };
        for s in page.secret_list() {
            let id = match s.arn().or_else(|| s.name()) {
                Some(v) => v.to_string(),
                None => continue,
            };
            let short = s.name().unwrap_or(&id).to_string();
            match client.get_resource_policy().secret_id(&id).send().await {
                Ok(p) => {
                    if let Some(policy) = p.resource_policy() {
                        loot.push((
                            "resource-policies".to_string(),
                            format!("secretsmanager-{}-{}.json", region, sanitize(&short)),
                            policy.as_bytes().to_vec(),
                        ));
                        process_policy(
                            &region,
                            "SecretsManager",
                            &short,
                            policy,
                            &caller_account,
                            &mut rows,
                        );
                    }
                }
                Err(e) => {
                    let s_err = e.to_string();
                    if s_err.contains("ResourceNotFound") {
                        continue;
                    }
                    eprintln!(
                        "{} secretsmanager get_resource_policy({}): {}",
                        "[-]".yellow(),
                        short,
                        s_err
                    );
                }
            }
        }
    }
    (rows, loot)
}

pub async fn run(
    factory: &ClientFactory,
    output: &OutputWriter,
    concurrency: usize,
) -> Result<()> {
    println!("\n{}", "[resource-trusts]".cyan().bold());

    let caller_account = match factory.sts().get_caller_identity().send().await {
        Ok(r) => r.account().unwrap_or_default().to_string(),
        Err(e) => {
            eprintln!("{} sts get_caller_identity failed: {}", "[-]".yellow(), e);
            String::new()
        }
    };
    let caller_account = Arc::new(caller_account);

    let factory_arc = Arc::new(factory.clone());
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let collected: Arc<Mutex<(Vec<ResourceTrustRow>, Vec<LootEntry>)>> =
        Arc::new(Mutex::new((Vec::new(), Vec::new())));

    let mut handles = Vec::new();

    // S3 — global
    {
        let factory = Arc::clone(&factory_arc);
        let caller = Arc::clone(&caller_account);
        let collected = Arc::clone(&collected);
        let sem = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (rows, loot) = scan_s3(factory, caller).await;
            let mut g = collected.lock().await;
            g.0.extend(rows);
            g.1.extend(loot);
        }));
    }

    for region in factory.regions.clone() {
        for kind in ["sns", "sqs", "lambda", "secrets"] {
            let factory = Arc::clone(&factory_arc);
            let caller = Arc::clone(&caller_account);
            let collected = Arc::clone(&collected);
            let sem = Arc::clone(&sem);
            let region = region.clone();
            let kind = kind.to_string();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let (rows, loot) = match kind.as_str() {
                    "sns" => scan_sns(factory, region, caller).await,
                    "sqs" => scan_sqs(factory, region, caller).await,
                    "lambda" => scan_lambda(factory, region, caller).await,
                    "secrets" => scan_secrets(factory, region, caller).await,
                    _ => (Vec::new(), Vec::new()),
                };
                let mut g = collected.lock().await;
                g.0.extend(rows);
                g.1.extend(loot);
            }));
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let (final_rows, loot_entries) = {
        let g = collected.lock().await;
        (g.0.clone(), g.1.clone())
    };

    // Write loot files synchronously on the main thread.
    for (dir, name, body) in loot_entries {
        if let Err(e) = output.loot_file(&dir, &name, &body) {
            eprintln!("{} loot_file({}): {}", "[-]".yellow(), name, e);
        }
    }

    if final_rows.is_empty() {
        println!("No resource policies found (or insufficient permissions).");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = final_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.service.clone(),
                r.resource_name.clone(),
                r.trusted_entity.clone(),
                r.action.clone(),
            ]
        })
        .collect();

    let headers = &["Region", "Service", "ResourceName", "TrustedEntity", "Action"];
    output.print_table(headers, &table_rows);
    output.write_table("resource-trusts", headers, &table_rows)?;
    output.write_csv("resource-trusts", &final_rows)?;
    output.write_json("resource-trusts", &final_rows)?;

    let external_count = final_rows.iter().filter(|r| r.external).count();
    if external_count > 0 {
        println!(
            "{} {} row(s) reference external/wildcard principals",
            "[!]".yellow().bold(),
            external_count
        );
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
