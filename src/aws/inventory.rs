use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct InventoryRow {
    pub region: String,
    pub service: String,
    pub count: usize,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[inventory]".cyan().bold());

    let regions = factory.regions.clone();
    let sem = Arc::new(Semaphore::new(concurrency));
    let factory = Arc::new(factory.clone());

    let pb = ProgressBar::new((regions.len() * 7) as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .unwrap(),
    );

    let mut handles = vec![];

    for region in &regions {
        let region = region.clone();
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);
        let pb = pb.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let mut rows = vec![];

            // EC2 instances
            pb.set_message(format!("{}: EC2", region));
            let count = count_ec2(&factory, &region).await.unwrap_or(0);
            rows.push(InventoryRow { region: region.clone(), service: "EC2 Instances".into(), count });
            pb.inc(1);

            // S3 buckets (global, only once per account — deduplicated by caller)
            pb.set_message(format!("{}: S3", region));
            let count = if region == "us-east-1" {
                count_s3(&factory).await.unwrap_or(0)
            } else {
                0
            };
            if region == "us-east-1" {
                rows.push(InventoryRow { region: "global".into(), service: "S3 Buckets".into(), count });
            }
            pb.inc(1);

            // IAM (global, only in us-east-1)
            if region == "us-east-1" {
                pb.set_message("IAM Users");
                let users = count_iam_users(&factory).await.unwrap_or(0);
                let roles = count_iam_roles(&factory).await.unwrap_or(0);
                rows.push(InventoryRow { region: "global".into(), service: "IAM Users".into(), count: users });
                rows.push(InventoryRow { region: "global".into(), service: "IAM Roles".into(), count: roles });
            }
            pb.inc(1);

            // Lambda
            pb.set_message(format!("{}: Lambda", region));
            let count = count_lambda(&factory, &region).await.unwrap_or(0);
            rows.push(InventoryRow { region: region.clone(), service: "Lambda Functions".into(), count });
            pb.inc(1);

            // RDS
            pb.set_message(format!("{}: RDS", region));
            let count = count_rds(&factory, &region).await.unwrap_or(0);
            rows.push(InventoryRow { region: region.clone(), service: "RDS Instances".into(), count });
            pb.inc(1);

            // ECS clusters
            pb.set_message(format!("{}: ECS", region));
            let count = count_ecs(&factory, &region).await.unwrap_or(0);
            rows.push(InventoryRow { region: region.clone(), service: "ECS Clusters".into(), count });
            pb.inc(1);

            // Secrets Manager
            pb.set_message(format!("{}: Secrets", region));
            let count = count_secrets(&factory, &region).await.unwrap_or(0);
            rows.push(InventoryRow { region: region.clone(), service: "Secrets".into(), count });
            pb.inc(1);

            rows
        });
        handles.push(handle);
    }

    let mut all_rows: Vec<InventoryRow> = vec![];
    for handle in handles {
        let rows = handle.await?;
        all_rows.extend(rows);
    }
    pb.finish_with_message("done");

    // Filter out zero-count rows for display, keep all for files
    let display_rows: Vec<Vec<String>> = all_rows
        .iter()
        .filter(|r| r.count > 0)
        .map(|r| vec![r.region.clone(), r.service.clone(), r.count.to_string()])
        .collect();

    if display_rows.is_empty() {
        println!("No resources found (or insufficient permissions).");
    } else {
        output.print_table(&["Region", "Service", "Count"], &display_rows);
    }

    let all_display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| vec![r.region.clone(), r.service.clone(), r.count.to_string()])
        .collect();

    output.write_table("inventory", &["Region", "Service", "Count"], &all_display)?;
    output.write_csv("inventory", &all_rows)?;
    output.write_json("inventory", &all_rows)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}

async fn count_ec2(factory: &ClientFactory, region: &str) -> Result<usize> {
    let client = factory.ec2(region);
    let mut count = 0;
    let mut paginator = client.describe_instances().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = page?;
        for r in page.reservations() {
            count += r.instances().len();
        }
    }
    Ok(count)
}

async fn count_s3(factory: &ClientFactory) -> Result<usize> {
    let client = factory.s3();
    let resp = client.list_buckets().send().await?;
    Ok(resp.buckets().len())
}

async fn count_iam_users(factory: &ClientFactory) -> Result<usize> {
    let client = factory.iam();
    let mut count = 0;
    let mut paginator = client.list_users().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.users().len();
    }
    Ok(count)
}

async fn count_iam_roles(factory: &ClientFactory) -> Result<usize> {
    let client = factory.iam();
    let mut count = 0;
    let mut paginator = client.list_roles().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.roles().len();
    }
    Ok(count)
}

async fn count_lambda(factory: &ClientFactory, region: &str) -> Result<usize> {
    let client = factory.lambda(region);
    let mut count = 0;
    let mut paginator = client.list_functions().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.functions().len();
    }
    Ok(count)
}

async fn count_rds(factory: &ClientFactory, region: &str) -> Result<usize> {
    let client = factory.rds(region);
    let mut count = 0;
    let mut paginator = client.describe_db_instances().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.db_instances().len();
    }
    Ok(count)
}

async fn count_ecs(factory: &ClientFactory, region: &str) -> Result<usize> {
    let client = factory.ecs(region);
    let mut count = 0;
    let mut paginator = client.list_clusters().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.cluster_arns().len();
    }
    Ok(count)
}

async fn count_secrets(factory: &ClientFactory, region: &str) -> Result<usize> {
    let client = factory.secretsmanager(region);
    let mut count = 0;
    let mut paginator = client.list_secrets().into_paginator().send();
    while let Some(page) = paginator.next().await {
        count += page?.secret_list().len();
    }
    Ok(count)
}
