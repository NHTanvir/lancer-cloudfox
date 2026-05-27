use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

/// CodeBuild's BatchGetProjects API hard-limits the names list to 5 entries.
const CODEBUILD_BATCH_SIZE: usize = 5;

#[derive(Serialize, Clone)]
pub struct EnvVarRow {
    pub region: String,
    pub service: String,
    pub resource_name: String,
    pub env_var_key: String,
    pub env_var_value: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[env-vars]".cyan().bold());

    let regions = factory.regions.clone();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let factory = Arc::new(factory.clone());

    let mut handles = Vec::with_capacity(regions.len());
    for region in regions {
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let lambda = collect_lambda(&factory, &region).await;
            let ecs = collect_ecs(&factory, &region).await;
            let cb = collect_codebuild(&factory, &region).await;
            (lambda, ecs, cb)
        }));
    }

    // Keep per-service per-region splits for the loot dir; flatten everything for the table.
    let mut rows: Vec<EnvVarRow> = Vec::new();
    let mut splits: Vec<(String, String, Vec<EnvVarRow>)> = Vec::new(); // (region, service, rows)

    for h in handles {
        if let Ok((lambda, ecs, cb)) = h.await {
            if !lambda.is_empty() {
                splits.push((
                    lambda[0].region.clone(),
                    "lambda".to_string(),
                    lambda.clone(),
                ));
                rows.extend(lambda);
            }
            if !ecs.is_empty() {
                splits.push((ecs[0].region.clone(), "ecs".to_string(), ecs.clone()));
                rows.extend(ecs);
            }
            if !cb.is_empty() {
                splits.push((cb[0].region.clone(), "codebuild".to_string(), cb.clone()));
                rows.extend(cb);
            }
        }
    }

    if rows.is_empty() {
        println!("No environment variables discovered (or insufficient permissions).");
        return Ok(());
    }

    let display_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.service.clone(),
                r.resource_name.clone(),
                r.env_var_key.clone(),
                r.env_var_value.clone(),
            ]
        })
        .collect();

    let headers = &["Region", "Service", "ResourceName", "EnvVarKey", "EnvVarValue"];
    output.print_table(headers, &display_rows);
    output.write_table("env-vars", headers, &display_rows)?;
    output.write_csv("env-vars", &rows)?;
    output.write_json("env-vars", &rows)?;

    // Per-service per-region split CSVs for easier grepping.
    for (region, service, split_rows) in &splits {
        let filename = format!("{}-{}.csv", service, region);
        let mut wtr = csv::Writer::from_writer(vec![]);
        for r in split_rows {
            wtr.serialize(r)?;
        }
        wtr.flush()?;
        let body = wtr.into_inner().unwrap_or_default();
        output.loot_file("env-vars", &filename, body)?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}

async fn collect_lambda(factory: &ClientFactory, region: &str) -> Vec<EnvVarRow> {
    let client = factory.lambda(region);
    let mut out = Vec::new();
    let mut pages = client.list_functions().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} lambda list_functions({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                break;
            }
        };
        for f in page.functions() {
            let name = f.function_name().unwrap_or_default().to_string();
            if let Some(env) = f.environment() {
                if let Some(vars) = env.variables() {
                    for (k, v) in vars {
                        out.push(EnvVarRow {
                            region: region.to_string(),
                            service: "lambda".to_string(),
                            resource_name: name.clone(),
                            env_var_key: k.clone(),
                            env_var_value: v.clone(),
                        });
                    }
                }
            }
        }
    }
    out
}

async fn collect_ecs(factory: &ClientFactory, region: &str) -> Vec<EnvVarRow> {
    let client = factory.ecs(region);
    let mut out = Vec::new();
    let mut pages = client.list_task_definitions().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} ecs list_task_definitions({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                break;
            }
        };
        for arn in page.task_definition_arns() {
            let desc = match client
                .describe_task_definition()
                .task_definition(arn)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "{} ecs describe_task_definition({}) failed: {}",
                        "[-]".yellow(),
                        arn,
                        e.into_service_error()
                    );
                    continue;
                }
            };

            if let Some(td) = desc.task_definition() {
                let resource_label = match (td.family(), Some(td.revision())) {
                    (Some(fam), Some(rev)) => format!("{fam}:{rev}"),
                    _ => arn.clone(),
                };
                for c in td.container_definitions() {
                    let container_name = c.name().unwrap_or("?").to_string();
                    for kv in c.environment() {
                        out.push(EnvVarRow {
                            region: region.to_string(),
                            service: "ecs".to_string(),
                            resource_name: format!("{resource_label}/{container_name}"),
                            env_var_key: kv.name().unwrap_or_default().to_string(),
                            env_var_value: kv.value().unwrap_or_default().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

async fn collect_codebuild(factory: &ClientFactory, region: &str) -> Vec<EnvVarRow> {
    let client = factory.codebuild(region);
    let mut out = Vec::new();

    let mut project_names: Vec<String> = Vec::new();
    let mut pages = client.list_projects().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} codebuild list_projects({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                break;
            }
        };
        for name in page.projects() {
            project_names.push(name.clone());
        }
    }

    // BatchGetProjects accepts at most 5 names per call.
    for chunk in project_names.chunks(CODEBUILD_BATCH_SIZE) {
        let mut req = client.batch_get_projects();
        for n in chunk {
            req = req.names(n.clone());
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{} codebuild batch_get_projects({}) failed: {}",
                    "[-]".yellow(),
                    region,
                    e.into_service_error()
                );
                continue;
            }
        };
        for proj in resp.projects() {
            let pname = proj.name().unwrap_or("?").to_string();
            if let Some(env) = proj.environment() {
                for ev in env.environment_variables() {
                    out.push(EnvVarRow {
                        region: region.to_string(),
                        service: "codebuild".to_string(),
                        resource_name: pname.clone(),
                        env_var_key: ev.name().to_string(),
                        env_var_value: ev.value().to_string(),
                    });
                }
            }
        }
    }

    out
}
