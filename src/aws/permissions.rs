use anyhow::Result;
use aws_sdk_iam::types::EntityType;
use colored::Colorize;
use serde::Serialize;
use serde_json::json;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct PermissionRow {
    #[serde(rename = "Type")]
    pub principal_type: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "PolicyType")]
    pub policy_type: String,
    #[serde(rename = "PolicyName")]
    pub policy_name: String,
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[permissions]".cyan().bold());

    let iam = factory.iam();
    let mut rows: Vec<PermissionRow> = Vec::new();

    // Use manual Marker pagination because we want to apply multiple Filter values.
    let mut marker: Option<String> = None;
    loop {
        let mut req = iam
            .get_account_authorization_details()
            .filter(EntityType::User)
            .filter(EntityType::Role)
            .filter(EntityType::Group)
            .filter(EntityType::LocalManagedPolicy)
            .filter(EntityType::AwsManagedPolicy);
        if let Some(m) = marker.as_ref() {
            req = req.marker(m.clone());
        }
        let page = match req.send().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} get_account_authorization_details failed: {}", "[-]".yellow(), e);
                break;
            }
        };

        // Users
        for user in page.user_detail_list() {
            let name = user.user_name().unwrap_or_default().to_string();
            // Attached managed policies
            for p in user.attached_managed_policies() {
                rows.push(PermissionRow {
                    principal_type: "User".to_string(),
                    name: name.clone(),
                    policy_type: "attached".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }
            // Inline policies
            for p in user.user_policy_list() {
                rows.push(PermissionRow {
                    principal_type: "User".to_string(),
                    name: name.clone(),
                    policy_type: "inline".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }

            // Loot: per-principal attached policies JSON
            if !name.is_empty() {
                let attached: Vec<_> = user
                    .attached_managed_policies()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyArn": p.policy_arn().unwrap_or_default(),
                        })
                    })
                    .collect();
                let inline: Vec<_> = user
                    .user_policy_list()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyDocument": p.policy_document().unwrap_or_default(),
                        })
                    })
                    .collect();
                let body = json!({
                    "Type": "User",
                    "Name": name,
                    "AttachedManagedPolicies": attached,
                    "InlinePolicies": inline,
                });
                let _ = output.loot_file(
                    "permissions",
                    &format!("{}.json", sanitize(&name)),
                    serde_json::to_vec_pretty(&body).unwrap_or_default(),
                );
            }
        }

        // Roles
        for role in page.role_detail_list() {
            let name = role.role_name().unwrap_or_default().to_string();
            for p in role.attached_managed_policies() {
                rows.push(PermissionRow {
                    principal_type: "Role".to_string(),
                    name: name.clone(),
                    policy_type: "attached".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }
            for p in role.role_policy_list() {
                rows.push(PermissionRow {
                    principal_type: "Role".to_string(),
                    name: name.clone(),
                    policy_type: "inline".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }

            if !name.is_empty() {
                let attached: Vec<_> = role
                    .attached_managed_policies()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyArn": p.policy_arn().unwrap_or_default(),
                        })
                    })
                    .collect();
                let inline: Vec<_> = role
                    .role_policy_list()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyDocument": p.policy_document().unwrap_or_default(),
                        })
                    })
                    .collect();
                let body = json!({
                    "Type": "Role",
                    "Name": name,
                    "AttachedManagedPolicies": attached,
                    "InlinePolicies": inline,
                });
                let _ = output.loot_file(
                    "permissions",
                    &format!("{}.json", sanitize(&name)),
                    serde_json::to_vec_pretty(&body).unwrap_or_default(),
                );
            }
        }

        // Groups
        for group in page.group_detail_list() {
            let name = group.group_name().unwrap_or_default().to_string();
            for p in group.attached_managed_policies() {
                rows.push(PermissionRow {
                    principal_type: "Group".to_string(),
                    name: name.clone(),
                    policy_type: "attached".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }
            for p in group.group_policy_list() {
                rows.push(PermissionRow {
                    principal_type: "Group".to_string(),
                    name: name.clone(),
                    policy_type: "inline".to_string(),
                    policy_name: p.policy_name().unwrap_or_default().to_string(),
                });
            }

            if !name.is_empty() {
                let attached: Vec<_> = group
                    .attached_managed_policies()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyArn": p.policy_arn().unwrap_or_default(),
                        })
                    })
                    .collect();
                let inline: Vec<_> = group
                    .group_policy_list()
                    .iter()
                    .map(|p| {
                        json!({
                            "PolicyName": p.policy_name().unwrap_or_default(),
                            "PolicyDocument": p.policy_document().unwrap_or_default(),
                        })
                    })
                    .collect();
                let body = json!({
                    "Type": "Group",
                    "Name": name,
                    "AttachedManagedPolicies": attached,
                    "InlinePolicies": inline,
                });
                let _ = output.loot_file(
                    "permissions",
                    &format!("{}.json", sanitize(&name)),
                    serde_json::to_vec_pretty(&body).unwrap_or_default(),
                );
            }
        }

        if page.is_truncated() {
            marker = page.marker().map(|s| s.to_string());
            if marker.is_none() {
                break;
            }
        } else {
            break;
        }
    }

    if rows.is_empty() {
        println!("No IAM permission data found (or insufficient permissions).");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.principal_type.clone(),
                r.name.clone(),
                r.policy_type.clone(),
                r.policy_name.clone(),
            ]
        })
        .collect();

    let headers = &["Type", "Name", "PolicyType", "PolicyName"];
    output.print_table(headers, &table_rows);
    output.write_table("permissions", headers, &table_rows)?;
    output.write_csv("permissions", &rows)?;
    output.write_json("permissions", &rows)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
