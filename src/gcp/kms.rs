use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:kms]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let kr_base = format!(
        "https://cloudkms.googleapis.com/v1/projects/{}/locations/-/keyRings",
        client.project
    );
    let mut url = kr_base.clone();
    let mut rings: Vec<String> = vec![];
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
        if let Some(items) = body.get("keyRings").and_then(|v| v.as_array()) {
            for it in items {
                if let Some(name) = it.get("name").and_then(|v| v.as_str()) {
                    rings.push(name.to_string());
                }
                json_data.push(it.clone());
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                url = format!("{}?pageToken={}", kr_base, t);
            }
            _ => break,
        }
    }

    for ring in &rings {
        let keys_base = format!("https://cloudkms.googleapis.com/v1/{}/cryptoKeys", ring);
        let mut k_url = keys_base.clone();
        let ring_short = ring.rsplit('/').next().unwrap_or(ring).to_string();
        loop {
            let resp = client
                .http
                .get(&k_url)
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
            if let Some(items) = body.get("cryptoKeys").and_then(|v| v.as_array()) {
                for it in items {
                    let key_name = it
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let purpose = it
                        .get("purpose")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let rotation = it
                        .get("rotationPeriod")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    rows.push(vec![ring_short.clone(), key_name, purpose, rotation]);
                    json_data.push(it.clone());
                }
            }
            match body.get("nextPageToken").and_then(|v| v.as_str()) {
                Some(t) if !t.is_empty() => {
                    k_url = format!("{}?pageToken={}", keys_base, t);
                }
                _ => break,
            }
        }
    }

    let headers = &["Keyring", "KeyName", "Purpose", "RotationPeriod"];
    output.print_table(headers, &rows);
    output.write_table("kms", headers, &rows)?;
    output.write_json("kms", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
