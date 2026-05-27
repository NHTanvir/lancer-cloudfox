use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct InstanceRow {
    pub region: String,
    pub instance_id: String,
    pub instance_type: String,
    pub state: String,
    pub private_ip: String,
    pub public_ip: String,
    pub iam_profile: String,
    pub launch_time: String,
    pub key_name: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[instances]".cyan().bold());
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
            let client = factory.ec2(&region);
            let mut rows: Vec<InstanceRow> = vec![];
            let mut paginator = client.describe_instances().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for reservation in page.reservations() {
                    for inst in reservation.instances() {
                        let iam_profile = inst
                            .iam_instance_profile()
                            .and_then(|p| p.arn())
                            .unwrap_or("")
                            .to_string();
                        let state = inst
                            .state()
                            .and_then(|s| s.name())
                            .map(|n| n.as_str().to_string())
                            .unwrap_or_default();
                        let launch_time = inst
                            .launch_time()
                            .map(|t| t.to_string())
                            .unwrap_or_default();
                        rows.push(InstanceRow {
                            region: region.clone(),
                            instance_id: inst.instance_id().unwrap_or("").to_string(),
                            instance_type: inst
                                .instance_type()
                                .map(|t| t.as_str().to_string())
                                .unwrap_or_default(),
                            state,
                            private_ip: inst.private_ip_address().unwrap_or("").to_string(),
                            public_ip: inst.public_ip_address().unwrap_or("").to_string(),
                            iam_profile,
                            launch_time,
                            key_name: inst.key_name().unwrap_or("").to_string(),
                        });
                    }
                }
            }
            rows
        });
        handles.push(handle);
    }
    let mut all_rows: Vec<InstanceRow> = vec![];
    for h in handles {
        all_rows.extend(h.await?);
    }

    let headers = &[
        "Region",
        "InstanceId",
        "Type",
        "State",
        "PrivateIP",
        "PublicIP",
        "IamProfile",
        "LaunchTime",
        "KeyName",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.instance_id.clone(),
                r.instance_type.clone(),
                r.state.clone(),
                r.private_ip.clone(),
                r.public_ip.clone(),
                r.iam_profile.clone(),
                r.launch_time.clone(),
                r.key_name.clone(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("instances", headers, &display)?;
    output.write_csv("instances", &all_rows)?;
    output.write_json("instances", &all_rows)?;
    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
