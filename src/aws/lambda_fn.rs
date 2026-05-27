use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct LambdaRow {
    pub region: String,
    pub function_name: String,
    pub runtime: String,
    pub role_arn: String,
    pub memory_size: i32,
    pub timeout: i32,
    pub vpc: bool,
    pub env_var_count: usize,
    pub last_modified: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[lambda]".cyan().bold());
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
            let client = factory.lambda(&region);
            let mut rows: Vec<LambdaRow> = vec![];
            let mut paginator = client.list_functions().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for f in page.functions() {
                    let runtime = f
                        .runtime()
                        .map(|r| r.as_str().to_string())
                        .unwrap_or_default();
                    let vpc = f
                        .vpc_config()
                        .map(|v| !v.subnet_ids().is_empty())
                        .unwrap_or(false);
                    let env_var_count = f
                        .environment()
                        .and_then(|e| e.variables())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    rows.push(LambdaRow {
                        region: region.clone(),
                        function_name: f.function_name().unwrap_or("").to_string(),
                        runtime,
                        role_arn: f.role().unwrap_or("").to_string(),
                        memory_size: f.memory_size().unwrap_or(0),
                        timeout: f.timeout().unwrap_or(0),
                        vpc,
                        env_var_count,
                        last_modified: f.last_modified().unwrap_or("").to_string(),
                    });
                }
            }
            rows
        });
        handles.push(handle);
    }
    let mut all_rows: Vec<LambdaRow> = vec![];
    for h in handles {
        all_rows.extend(h.await?);
    }

    let headers = &[
        "Region",
        "FunctionName",
        "Runtime",
        "RoleArn",
        "MemorySize",
        "Timeout",
        "VPC?",
        "EnvVarCount",
        "LastModified",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.function_name.clone(),
                r.runtime.clone(),
                r.role_arn.clone(),
                r.memory_size.to_string(),
                r.timeout.to_string(),
                if r.vpc { "yes".to_string() } else { "no".to_string() },
                r.env_var_count.to_string(),
                r.last_modified.clone(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("lambda", headers, &display)?;
    output.write_csv("lambda", &all_rows)?;
    output.write_json("lambda", &all_rows)?;
    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
