use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::collections::HashMap;

use crate::azure::client::AzureClient;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct RbacRow {
    pub scope: String,
    pub principal_type: String,
    pub principal_id: String,
    pub role_name: String,
}

async fn paginate(
    client: &AzureClient,
    first_url: String,
) -> Result<Vec<serde_json::Value>> {
    let auth = format!("Bearer {}", client.access_token);
    let mut url = first_url;
    let mut out: Vec<serde_json::Value> = Vec::new();
    loop {
        let body: serde_json::Value = client
            .http
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await
            .context("Azure RBAC request failed")?
            .json()
            .await
            .context("Failed to decode RBAC JSON")?;

        if let Some(arr) = body.get("value").and_then(|v| v.as_array()) {
            for item in arr {
                out.push(item.clone());
            }
        }

        match body.get("nextLink").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => url = n.to_string(),
            _ => break,
        }
    }
    Ok(out)
}

pub async fn run(client: &AzureClient, output: &OutputWriter) -> Result<()> {
    // Role definitions: id -> role name
    let defs_url = format!(
        "https://management.azure.com/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01",
        client.subscription_id
    );
    let definitions = paginate(client, defs_url).await?;
    let mut def_map: HashMap<String, String> = HashMap::new();
    for d in &definitions {
        let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = d
            .get("properties")
            .and_then(|p| p.get("roleName"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if !id.is_empty() {
            def_map.insert(id, name);
        }
    }

    // Role assignments
    let assignments_url = format!(
        "https://management.azure.com/subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
        client.subscription_id
    );
    let assignments = paginate(client, assignments_url).await?;

    let high_privilege = ["Owner", "Contributor", "User Access Administrator"];
    let mut high_lines: Vec<String> = Vec::new();

    let mut rows_struct: Vec<RbacRow> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();

    for a in &assignments {
        let props = a.get("properties").cloned().unwrap_or(serde_json::Value::Null);
        let scope = props
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let principal_type = props
            .get("principalType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let principal_id = props
            .get("principalId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let role_def_id = props
            .get("roleDefinitionId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let role_name = def_map
            .get(&role_def_id)
            .cloned()
            .unwrap_or_else(|| role_def_id.rsplit('/').next().unwrap_or("unknown").to_string());

        if high_privilege.iter().any(|r| *r == role_name) {
            high_lines.push(format!(
                "{}\t{}\t{}\t{}",
                scope, principal_type, principal_id, role_name
            ));
        }

        rows.push(vec![
            scope.clone(),
            principal_type.clone(),
            principal_id.clone(),
            role_name.clone(),
        ]);
        rows_struct.push(RbacRow {
            scope,
            principal_type,
            principal_id,
            role_name,
        });
    }

    let headers = &["Scope", "PrincipalType", "PrincipalId", "RoleName"];

    println!("\n{}", "[azure rbac]".cyan().bold());
    output.print_table(headers, &rows);

    output.write_table("rbac", headers, &rows)?;
    output.write_csv("rbac", &rows_struct)?;
    output.write_json("rbac", &assignments)?;

    if !high_lines.is_empty() {
        let body = format!(
            "# High-privilege role assignments (Owner / Contributor / User Access Administrator)\n# scope\tprincipalType\tprincipalId\troleName\n{}\n",
            high_lines.join("\n")
        );
        output.loot_file("rbac", "high-privilege-assignments.txt", body.as_bytes())?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
