use anyhow::Result;
use colored::Colorize;
use serde_json::Value;
use std::collections::BTreeMap;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:inventory]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut json_data: Vec<Value> = vec![];

    let mut url = format!(
        "https://cloudasset.googleapis.com/v1/projects/{}/assets?contentType=RESOURCE",
        client.project
    );
    loop {
        let resp = client
            .http
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await?;
        if !resp.status().is_success() {
            eprintln!(
                "warn: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
            break;
        }
        let body: Value = resp.json().await?;
        if let Some(items) = body.get("assets").and_then(|v| v.as_array()) {
            for it in items {
                let asset_type = it
                    .get("assetType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                *counts.entry(asset_type).or_insert(0) += 1;
                json_data.push(it.clone());
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                url = format!(
                    "https://cloudasset.googleapis.com/v1/projects/{}/assets?contentType=RESOURCE&pageToken={}",
                    client.project, t
                );
            }
            _ => break,
        }
    }

    let mut rows: Vec<Vec<String>> = vec![];
    for (k, v) in &counts {
        rows.push(vec![k.clone(), v.to_string()]);
    }

    let headers = &["AssetType", "Count"];
    output.print_table(headers, &rows);
    output.write_table("inventory", headers, &rows)?;
    output.write_json("inventory", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
