use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:gke]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let url = format!(
        "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
        client.project
    );
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
    } else {
        let body: Value = resp.json().await?;
        if let Some(items) = body.get("clusters").and_then(|v| v.as_array()) {
            for it in items {
                let name = it
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let location = it
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let version = it
                    .get("currentMasterVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let endpoint = it
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let node_count = it
                    .get("currentNodeCount")
                    .and_then(|v| v.as_i64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "0".to_string());
                rows.push(vec![name, location, version, endpoint, node_count]);
                json_data.push(it.clone());
            }
        }
    }

    let headers = &["ClusterName", "Location", "Version", "Endpoint", "NodeCount"];
    output.print_table(headers, &rows);
    output.write_table("gke", headers, &rows)?;
    output.write_json("gke", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
