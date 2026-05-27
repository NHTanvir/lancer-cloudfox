use anyhow::Result;
use colored::Colorize;
use serde_json::Value;
use std::process::Command;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:whoami]".cyan().bold());

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let out = Command::new("gcloud")
        .args(["auth", "list", "--format=json"])
        .output();

    if let Ok(out) = out {
        if out.status.success() {
            if let Ok(s) = String::from_utf8(out.stdout) {
                if let Ok(v) = serde_json::from_str::<Value>(&s) {
                    if let Some(arr) = v.as_array() {
                        for acc in arr {
                            let account = acc
                                .get("account")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let status = acc
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let acc_type = if account.ends_with(".iam.gserviceaccount.com") {
                                "ServiceAccount"
                            } else if status.eq_ignore_ascii_case("ACTIVE") {
                                "User"
                            } else {
                                "User(Inactive)"
                            };
                            rows.push(vec![
                                account.clone(),
                                client.project.clone(),
                                acc_type.to_string(),
                            ]);
                            json_data.push(acc.clone());
                        }
                    }
                }
            }
        }
    }

    if rows.is_empty() {
        rows.push(vec![
            "(unknown)".to_string(),
            client.project.clone(),
            "Unknown".to_string(),
        ]);
    }

    let headers = &["Account", "ActiveProject", "Type"];
    output.print_table(headers, &rows);
    output.write_table("whoami", headers, &rows)?;
    output.write_json("whoami", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
