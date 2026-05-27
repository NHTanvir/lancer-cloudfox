use anyhow::Result;
use aws_sdk_cloudformation::types::StackStatus;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct StackRow {
    pub region: String,
    pub stack_name: String,
    pub status: String,
    pub drift_status: String,
    pub creation_time: String,
    pub output_count: usize,
}

#[derive(Serialize, Clone)]
struct StackOutputDump {
    region: String,
    stack_name: String,
    outputs: Vec<StackOutputEntry>,
}

#[derive(Serialize, Clone)]
struct StackOutputEntry {
    output_key: String,
    output_value: String,
    description: String,
    export_name: String,
}

fn is_active_status(s: &StackStatus) -> bool {
    matches!(
        s,
        StackStatus::CreateComplete
            | StackStatus::UpdateComplete
            | StackStatus::UpdateRollbackComplete
            | StackStatus::RollbackComplete
            | StackStatus::ImportComplete
            | StackStatus::UpdateCompleteCleanupInProgress
            | StackStatus::UpdateRollbackCompleteCleanupInProgress
    )
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[cloudformation]".cyan().bold());
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
            let client = factory.cloudformation(&region);
            let mut rows: Vec<StackRow> = vec![];
            let mut dumps: Vec<StackOutputDump> = vec![];

            let mut stack_names: Vec<String> = vec![];
            let mut paginator = client.list_stacks().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for s in page.stack_summaries() {
                    if let Some(status) = s.stack_status() {
                        if is_active_status(status) {
                            if let Some(name) = s.stack_name() {
                                stack_names.push(name.to_string());
                            }
                        }
                    }
                }
            }

            for name in stack_names {
                let resp = match client.describe_stacks().stack_name(&name).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                for stack in resp.stacks() {
                    let outputs: Vec<StackOutputEntry> = stack
                        .outputs()
                        .iter()
                        .map(|o| StackOutputEntry {
                            output_key: o.output_key().unwrap_or("").to_string(),
                            output_value: o.output_value().unwrap_or("").to_string(),
                            description: o.description().unwrap_or("").to_string(),
                            export_name: o.export_name().unwrap_or("").to_string(),
                        })
                        .collect();
                    rows.push(StackRow {
                        region: region.clone(),
                        stack_name: stack.stack_name().unwrap_or("").to_string(),
                        status: stack
                            .stack_status()
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_default(),
                        drift_status: stack
                            .drift_information()
                            .and_then(|d| d.stack_drift_status().map(|s| s.as_str().to_string()))
                            .unwrap_or_default(),
                        creation_time: stack
                            .creation_time()
                            .map(|t| t.to_string())
                            .unwrap_or_default(),
                        output_count: outputs.len(),
                    });
                    if !outputs.is_empty() {
                        dumps.push(StackOutputDump {
                            region: region.clone(),
                            stack_name: stack.stack_name().unwrap_or("").to_string(),
                            outputs,
                        });
                    }
                }
            }
            (rows, dumps)
        });
        handles.push(handle);
    }

    let mut all_rows: Vec<StackRow> = vec![];
    let mut all_dumps: Vec<StackOutputDump> = vec![];
    for h in handles {
        let (rows, dumps) = h.await?;
        all_rows.extend(rows);
        all_dumps.extend(dumps);
    }

    let headers = &[
        "Region",
        "StackName",
        "Status",
        "DriftStatus",
        "CreationTime",
        "OutputCount",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.stack_name.clone(),
                r.status.clone(),
                r.drift_status.clone(),
                r.creation_time.clone(),
                r.output_count.to_string(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("cloudformation", headers, &display)?;
    output.write_csv("cloudformation", &all_rows)?;
    output.write_json("cloudformation", &all_rows)?;

    for dump in &all_dumps {
        let body = serde_json::to_vec_pretty(dump)?;
        let safe = dump.stack_name.replace('/', "_");
        output.loot_file(
            "cloudformation",
            &format!("{}-outputs.json", safe),
            body,
        )?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
