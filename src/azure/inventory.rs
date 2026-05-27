use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::azure::client::AzureClient;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct InventoryRow {
    pub r#type: String,
    pub location: String,
    pub count: u64,
}

pub async fn run(client: &AzureClient, output: &OutputWriter) -> Result<()> {
    let auth = format!("Bearer {}", client.access_token);
    let mut url = format!(
        "https://management.azure.com/subscriptions/{}/resources?api-version=2021-04-01",
        client.subscription_id
    );

    // (type, location) -> count
    let mut buckets: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut all_resources: Vec<serde_json::Value> = Vec::new();

    loop {
        let body: serde_json::Value = client
            .http
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await
            .context("Azure resources list request failed")?
            .json()
            .await
            .context("Failed to decode resources list JSON")?;

        if let Some(arr) = body.get("value").and_then(|v| v.as_array()) {
            for item in arr {
                let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let loc = item
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("global")
                    .to_string();
                *buckets.entry((t, loc)).or_insert(0) += 1;
                all_resources.push(item.clone());
            }
        }

        match body.get("nextLink").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => url = n.to_string(),
            _ => break,
        }
    }

    let mut rows_struct: Vec<InventoryRow> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for ((t, loc), count) in &buckets {
        rows.push(vec![t.clone(), loc.clone(), count.to_string()]);
        rows_struct.push(InventoryRow {
            r#type: t.clone(),
            location: loc.clone(),
            count: *count,
        });
    }

    let headers = &["Type", "Location", "Count"];

    println!("\n{}", "[azure inventory]".cyan().bold());
    output.print_table(headers, &rows);

    output.write_table("inventory", headers, &rows)?;
    output.write_csv("inventory", &rows_struct)?;
    output.write_json("inventory", &all_resources)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
