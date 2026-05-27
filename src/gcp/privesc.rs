use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use super::iam::fetch_iam_policy;
use crate::output::OutputWriter;

const DANGEROUS_ROLES: &[(&str, &str)] = &[
    (
        "roles/owner",
        "Full project ownership, can grant any role, manage IAM",
    ),
    (
        "roles/editor",
        "Broad write access across many services; can often pivot",
    ),
    (
        "roles/iam.serviceAccountTokenCreator",
        "Can mint OAuth tokens for any service account",
    ),
    (
        "roles/iam.serviceAccountUser",
        "Can act as service accounts (impersonate when attached to compute/cf)",
    ),
    (
        "roles/iam.serviceAccountKeyAdmin",
        "Can create SA keys -> long-lived credential exfiltration",
    ),
    (
        "roles/iam.workloadIdentityUser",
        "Can impersonate SAs via Workload Identity (GKE/external)",
    ),
    (
        "roles/iam.serviceAccountAdmin",
        "Can create/manage service accounts and their IAM",
    ),
    (
        "roles/resourcemanager.projectIamAdmin",
        "Can modify project IAM policy -> grant any role",
    ),
];

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:privesc]".cyan().bold());

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let policy = match fetch_iam_policy(client).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warn: {}", e);
            Value::Null
        }
    };

    if let Some(bindings) = policy.get("bindings").and_then(|v| v.as_array()) {
        for binding in bindings {
            let role = binding
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let why = DANGEROUS_ROLES
                .iter()
                .find(|(r, _)| *r == role.as_str())
                .map(|(_, w)| *w);
            if let Some(why) = why {
                if let Some(members) = binding.get("members").and_then(|v| v.as_array()) {
                    for m in members {
                        let member = m.as_str().unwrap_or("").to_string();
                        rows.push(vec![member.clone(), role.clone(), why.to_string()]);
                        json_data.push(serde_json::json!({
                            "member": member,
                            "role": role,
                            "why": why,
                        }));
                    }
                }
            }
        }
    }

    let headers = &["Member", "DangerousRole", "Why"];
    output.print_table(headers, &rows);
    output.write_table("privesc", headers, &rows)?;
    output.write_json("privesc", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
