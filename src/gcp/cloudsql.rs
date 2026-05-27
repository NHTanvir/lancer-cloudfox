use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:cloudsql]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!(
        "https://sqladmin.googleapis.com/v1/projects/{}/instances",
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
        if let Some(items) = body.get("items").and_then(|v| v.as_array()) {
            for it in items {
                let name = it
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let region = it
                    .get("region")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let db_version = it
                    .get("databaseVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (engine, version) = if let Some(idx) = db_version.find('_') {
                    (
                        db_version[..idx].to_string(),
                        db_version[idx + 1..].to_string(),
                    )
                } else {
                    (db_version.clone(), String::new())
                };
                let state = it
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut public_ip = String::new();
                if let Some(addrs) = it.get("ipAddresses").and_then(|v| v.as_array()) {
                    for a in addrs {
                        let t = a.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if t == "PRIMARY" || t == "OUTGOING" {
                            if let Some(ip) = a.get("ipAddress").and_then(|v| v.as_str()) {
                                public_ip = ip.to_string();
                                break;
                            }
                        }
                    }
                }
                rows.push(vec![name, region, engine, version, state, public_ip]);
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

    let headers = &["Name", "Region", "Engine", "Version", "State", "PublicIp"];
    output.print_table(headers, &rows);
    output.write_table("cloudsql", headers, &rows)?;
    output.write_json("cloudsql", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
