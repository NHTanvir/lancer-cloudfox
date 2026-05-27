use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:storage]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!("https://storage.googleapis.com/storage/v1/b?project={}", client.project);
    let mut url = base.clone();
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
        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
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
                let class = it
                    .get("storageClass")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let pap = it
                    .get("iamConfiguration")
                    .and_then(|v| v.get("publicAccessPrevention"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("inherited")
                    .to_string();
                rows.push(vec![name, location, class, pap]);
                json_data.push(it.clone());
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                url = format!("{}&pageToken={}", base, t);
            }
            _ => break,
        }
    }

    let headers = &["Bucket", "Location", "StorageClass", "PublicAccessPrevention"];
    output.print_table(headers, &rows);
    output.write_table("storage", headers, &rows)?;
    output.write_json("storage", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
