use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct EksRow {
    pub region: String,
    pub cluster_name: String,
    pub version: String,
    pub endpoint_public: bool,
    pub status: String,
    pub node_group_count: usize,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[eks]".cyan().bold());
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
            let client = factory.eks(&region);
            let mut rows: Vec<EksRow> = vec![];
            let mut loot_entries: Vec<(String, String)> = vec![]; // (cluster, command)

            let mut cluster_names: Vec<String> = vec![];
            let mut paginator = client.list_clusters().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for c in page.clusters() {
                    cluster_names.push(c.to_string());
                }
            }

            for name in cluster_names {
                let resp = match client.describe_cluster().name(&name).send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let cluster = match resp.cluster() {
                    Some(c) => c,
                    None => continue,
                };
                let version = cluster.version().unwrap_or("").to_string();
                let endpoint_public = cluster
                    .resources_vpc_config()
                    .map(|v| v.endpoint_public_access())
                    .unwrap_or(false);
                let status = cluster
                    .status()
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default();

                // Node groups
                let node_group_count: usize;
                let mut ng_paginator = client
                    .list_nodegroups()
                    .cluster_name(&name)
                    .into_paginator()
                    .send();
                let mut ng_names: Vec<String> = vec![];
                while let Some(page) = ng_paginator.next().await {
                    let page = match page {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    for ng in page.nodegroups() {
                        ng_names.push(ng.to_string());
                    }
                }
                node_group_count = ng_names.len();
                // Probe each nodegroup for instance types (not stored, but exercises API per spec).
                for ng_name in &ng_names {
                    let _ = client
                        .describe_nodegroup()
                        .cluster_name(&name)
                        .nodegroup_name(ng_name)
                        .send()
                        .await;
                }

                rows.push(EksRow {
                    region: region.clone(),
                    cluster_name: name.clone(),
                    version,
                    endpoint_public,
                    status,
                    node_group_count,
                });
                let cmd = format!(
                    "aws eks update-kubeconfig --name {} --region {}\n",
                    name, region
                );
                loot_entries.push((name, cmd));
            }

            (rows, loot_entries, region)
        });
        handles.push(handle);
    }

    let mut all_rows: Vec<EksRow> = vec![];
    let mut all_loot: Vec<(String, String, String)> = vec![]; // (cluster, region, cmd)
    for h in handles {
        let (rows, loot, region) = h.await?;
        all_rows.extend(rows);
        for (c, cmd) in loot {
            all_loot.push((c, region.clone(), cmd));
        }
    }

    let headers = &[
        "Region",
        "ClusterName",
        "Version",
        "EndpointPublic",
        "Status",
        "NodeGroupCount",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.cluster_name.clone(),
                r.version.clone(),
                if r.endpoint_public { "yes".to_string() } else { "no".to_string() },
                r.status.clone(),
                r.node_group_count.to_string(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("eks", headers, &display)?;
    output.write_csv("eks", &all_rows)?;
    output.write_json("eks", &all_rows)?;

    for (cluster, _region, cmd) in &all_loot {
        let safe = cluster.replace('/', "_");
        output.loot_file("eks", &format!("eks-tokens-{}.txt", safe), cmd.as_bytes())?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
