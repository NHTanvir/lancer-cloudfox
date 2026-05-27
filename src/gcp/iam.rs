use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn fetch_iam_policy(client: &GcpClient) -> Result<Value> {
    let auth = format!("Bearer {}", client.access_token);
    let url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
        client.project
    );
    let resp = client
        .http
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("getIamPolicy failed: {} {}", status, text);
    }
    Ok(resp.json().await?)
}

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:iam]".cyan().bold());

    let mut rows: Vec<Vec<String>> = vec![];
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
            if let Some(members) = binding.get("members").and_then(|v| v.as_array()) {
                for m in members {
                    let member = m.as_str().unwrap_or("").to_string();
                    let mtype = member.split(':').next().unwrap_or("").to_string();
                    rows.push(vec![role.clone(), member, mtype]);
                }
            }
        }
    }

    let headers = &["Role", "Member", "MemberType"];
    output.print_table(headers, &rows);
    output.write_table("iam", headers, &rows)?;
    output.write_json("iam", &policy)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
