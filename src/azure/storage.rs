use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use crate::azure::client::AzureClient;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct StorageRow {
    pub name: String,
    pub location: String,
    pub public_blob_access: String,
    pub https_only: String,
    pub default_action: String,
    pub encrypted: String,
}

pub async fn run(client: &AzureClient, output: &OutputWriter) -> Result<()> {
    let auth = format!("Bearer {}", client.access_token);
    let mut url = format!(
        "https://management.azure.com/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
        client.subscription_id
    );

    let mut accounts: Vec<serde_json::Value> = Vec::new();
    loop {
        let body: serde_json::Value = client
            .http
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await
            .context("Azure storageAccounts list failed")?
            .json()
            .await
            .context("Failed to decode storageAccounts JSON")?;

        if let Some(arr) = body.get("value").and_then(|v| v.as_array()) {
            for a in arr {
                accounts.push(a.clone());
            }
        }
        match body.get("nextLink").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => url = n.to_string(),
            _ => break,
        }
    }

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut rows_struct: Vec<StorageRow> = Vec::new();

    for a in &accounts {
        let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let location = a.get("location").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let props = a.get("properties").cloned().unwrap_or(serde_json::Value::Null);

        let public_blob_access = props
            .get("allowBlobPublicAccess")
            .and_then(|v| v.as_bool())
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let https_only = props
            .get("supportsHttpsTrafficOnly")
            .and_then(|v| v.as_bool())
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let default_action = props
            .get("networkAcls")
            .and_then(|n| n.get("defaultAction"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let encrypted = props
            .get("encryption")
            .and_then(|e| e.get("services"))
            .map(|svcs| {
                let mut any_enabled = false;
                if let Some(obj) = svcs.as_object() {
                    for (_k, v) in obj {
                        if v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false) {
                            any_enabled = true;
                        }
                    }
                }
                any_enabled.to_string()
            })
            .unwrap_or_else(|| "unknown".to_string());

        rows.push(vec![
            name.clone(),
            location.clone(),
            public_blob_access.clone(),
            https_only.clone(),
            default_action.clone(),
            encrypted.clone(),
        ]);
        rows_struct.push(StorageRow {
            name,
            location,
            public_blob_access,
            https_only,
            default_action,
            encrypted,
        });
    }

    let headers = &[
        "Name",
        "Location",
        "PublicBlobAccess",
        "HttpsOnly",
        "DefaultAction",
        "Encrypted",
    ];

    println!("\n{}", "[azure storage]".cyan().bold());
    output.print_table(headers, &rows);

    output.write_table("storage", headers, &rows)?;
    output.write_csv("storage", &rows_struct)?;
    output.write_json("storage", &accounts)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
