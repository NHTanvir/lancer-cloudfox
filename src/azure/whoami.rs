use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::process::Command;

use crate::azure::client::AzureClient;
use crate::output::OutputWriter;

#[derive(Serialize)]
pub struct WhoamiRow {
    pub subscription_id: String,
    pub subscription_name: String,
    pub tenant_id: String,
    pub user: String,
}

pub async fn run(_client: &AzureClient, output: &OutputWriter) -> Result<()> {
    let out = Command::new("az")
        .args(["account", "show", "--output", "json"])
        .output()
        .context("Failed to invoke `az account show`")?;
    if !out.status.success() {
        anyhow::bail!("`az account show` failed. Run `az login` first.");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)
        .context("Failed to parse `az account show` output as JSON")?;

    let subscription_id = v.get("id").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
    let subscription_name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let tenant_id = v
        .get("tenantId")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let user = v
        .get("user")
        .and_then(|u| u.get("name"))
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();

    let row = WhoamiRow {
        subscription_id: subscription_id.clone(),
        subscription_name: subscription_name.clone(),
        tenant_id: tenant_id.clone(),
        user: user.clone(),
    };

    let headers = &["SubscriptionId", "SubscriptionName", "TenantId", "User"];
    let rows = vec![vec![
        subscription_id.clone(),
        subscription_name.clone(),
        tenant_id.clone(),
        user.clone(),
    ]];

    println!("\n{}", "[azure whoami]".cyan().bold());
    output.print_table(headers, &rows);

    output.write_table("whoami", headers, &rows)?;
    output.write_csv("whoami", &[&row])?;
    output.write_json("whoami", &row)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
