use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:cloudrun]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!(
        "https://run.googleapis.com/v2/projects/{}/locations/-/services",
        client.project
    );
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
        if let Some(items) = body.get("services").and_then(|v| v.as_array()) {
            for it in items {
                let full_name = it.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let service = full_name.rsplit('/').next().unwrap_or("").to_string();
                // name shape: projects/X/locations/REGION/services/NAME
                let region = full_name
                    .split('/')
                    .collect::<Vec<_>>()
                    .windows(2)
                    .find(|w| w[0] == "locations")
                    .map(|w| w[1].to_string())
                    .unwrap_or_default();
                let uri = it
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ingress = it
                    .get("ingress")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![service, region, uri, ingress]);
                json_data.push(it.clone());
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                url = format!("{}?pageToken={}", base, t);
            }
            _ => break,
        }
    }

    let headers = &["Service", "Region", "Url", "Ingress"];
    output.print_table(headers, &rows);
    output.write_table("cloudrun", headers, &rows)?;
    output.write_json("cloudrun", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
