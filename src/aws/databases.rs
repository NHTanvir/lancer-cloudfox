use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone, Default)]
pub struct DatabaseRow {
    pub region: String,
    pub service: String,
    pub identifier: String,
    pub engine: String,
    pub version: String,
    pub endpoint: String,
    pub port: String,
    pub public: String,
    pub encrypted: String,
    pub item_count: String,
    pub stream_enabled: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[databases]".cyan().bold());
    let regions = factory.regions.clone();
    let sem = Arc::new(Semaphore::new(concurrency));
    let factory = Arc::new(factory.clone());

    let mut handles = vec![];
    for region in &regions {
        let region = region.clone();
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let mut rows: Vec<DatabaseRow> = vec![];

            // RDS
            let rds = factory.rds(&region);
            let mut paginator = rds.describe_db_instances().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for inst in page.db_instances() {
                    let endpoint = inst
                        .endpoint()
                        .and_then(|e| e.address())
                        .unwrap_or("")
                        .to_string();
                    let port = inst
                        .endpoint()
                        .and_then(|e| e.port())
                        .map(|p| p.to_string())
                        .unwrap_or_default();
                    rows.push(DatabaseRow {
                        region: region.clone(),
                        service: "RDS".to_string(),
                        identifier: inst.db_instance_identifier().unwrap_or("").to_string(),
                        engine: inst.engine().unwrap_or("").to_string(),
                        version: inst.engine_version().unwrap_or("").to_string(),
                        endpoint,
                        port,
                        public: if inst.publicly_accessible().unwrap_or(false) {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                        encrypted: if inst.storage_encrypted().unwrap_or(false) {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                        item_count: String::new(),
                        stream_enabled: String::new(),
                    });
                }
            }

            // DynamoDB
            let ddb = factory.dynamodb(&region);
            let mut tables: Vec<String> = vec![];
            let mut paginator = ddb.list_tables().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for name in page.table_names() {
                    tables.push(name.to_string());
                }
            }
            for table_name in tables {
                if let Ok(resp) = ddb.describe_table().table_name(&table_name).send().await {
                    if let Some(desc) = resp.table() {
                        let encrypted = desc
                            .sse_description()
                            .and_then(|s| s.status())
                            .map(|s| {
                                matches!(
                                    s,
                                    aws_sdk_dynamodb::types::SseStatus::Enabled
                                        | aws_sdk_dynamodb::types::SseStatus::Enabling
                                )
                            })
                            .unwrap_or(false);
                        let stream_enabled = desc
                            .stream_specification()
                            .map(|s| s.stream_enabled())
                            .unwrap_or(false);
                        rows.push(DatabaseRow {
                            region: region.clone(),
                            service: "DynamoDB".to_string(),
                            identifier: desc.table_name().unwrap_or(&table_name).to_string(),
                            engine: String::new(),
                            version: String::new(),
                            endpoint: String::new(),
                            port: String::new(),
                            public: String::new(),
                            encrypted: if encrypted {
                                "yes".to_string()
                            } else {
                                "no".to_string()
                            },
                            item_count: desc
                                .item_count()
                                .map(|n| n.to_string())
                                .unwrap_or_default(),
                            stream_enabled: if stream_enabled {
                                "yes".to_string()
                            } else {
                                "no".to_string()
                            },
                        });
                    }
                }
            }
            rows
        });
        handles.push(handle);
    }
    let mut all_rows: Vec<DatabaseRow> = vec![];
    for h in handles {
        all_rows.extend(h.await?);
    }

    let headers = &[
        "Region",
        "Service",
        "Identifier",
        "Engine",
        "Version",
        "Endpoint",
        "Port",
        "Public?",
        "Encrypted?",
        "ItemCount",
        "StreamEnabled?",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.service.clone(),
                r.identifier.clone(),
                r.engine.clone(),
                r.version.clone(),
                r.endpoint.clone(),
                r.port.clone(),
                r.public.clone(),
                r.encrypted.clone(),
                r.item_count.clone(),
                r.stream_enabled.clone(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("databases", headers, &display)?;
    output.write_csv("databases", &all_rows)?;
    output.write_json("databases", &all_rows)?;
    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
