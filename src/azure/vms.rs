use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use crate::azure::client::AzureClient;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct VmRow {
    pub name: String,
    pub location: String,
    pub size: String,
    pub os_type: String,
    pub admin_user: String,
    pub identity_type: String,
}

pub async fn run(client: &AzureClient, output: &OutputWriter) -> Result<()> {
    let auth = format!("Bearer {}", client.access_token);
    let mut url = format!(
        "https://management.azure.com/subscriptions/{}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01",
        client.subscription_id
    );

    let mut vms: Vec<serde_json::Value> = Vec::new();
    loop {
        let body: serde_json::Value = client
            .http
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await
            .context("Azure virtualMachines list failed")?
            .json()
            .await
            .context("Failed to decode virtualMachines JSON")?;

        if let Some(arr) = body.get("value").and_then(|v| v.as_array()) {
            for v in arr {
                vms.push(v.clone());
            }
        }

        match body.get("nextLink").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => url = n.to_string(),
            _ => break,
        }
    }

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut rows_struct: Vec<VmRow> = Vec::new();

    for v in &vms {
        let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let location = v.get("location").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let props = v.get("properties").cloned().unwrap_or(serde_json::Value::Null);
        let size = props
            .get("hardwareProfile")
            .and_then(|h| h.get("vmSize"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let admin_user = props
            .get("osProfile")
            .and_then(|o| o.get("adminUsername"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let os_type = props
            .get("storageProfile")
            .and_then(|s| s.get("osDisk"))
            .and_then(|d| d.get("osType"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let identity_type = v
            .get("identity")
            .and_then(|i| i.get("type"))
            .and_then(|x| x.as_str())
            .unwrap_or("None")
            .to_string();

        rows.push(vec![
            name.clone(),
            location.clone(),
            size.clone(),
            os_type.clone(),
            admin_user.clone(),
            identity_type.clone(),
        ]);
        rows_struct.push(VmRow {
            name,
            location,
            size,
            os_type,
            admin_user,
            identity_type,
        });
    }

    let headers = &["Name", "Location", "Size", "OsType", "AdminUser", "IdentityType"];

    println!("\n{}", "[azure vms]".cyan().bold());
    output.print_table(headers, &rows);

    output.write_table("vms", headers, &rows)?;
    output.write_csv("vms", &rows_struct)?;
    output.write_json("vms", &vms)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
