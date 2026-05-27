use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:functions]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!(
        "https://cloudfunctions.googleapis.com/v2/projects/{}/locations/-/functions",
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
        if let Some(items) = body.get("functions").and_then(|v| v.as_array()) {
            for it in items {
                let name = it
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let runtime = it
                    .get("buildConfig")
                    .and_then(|v| v.get("runtime"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let state = it
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let url_field = it
                    .get("serviceConfig")
                    .and_then(|v| v.get("uri"))
                    .and_then(|v| v.as_str())
                    .or_else(|| it.get("url").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                rows.push(vec![name, runtime, state, url_field]);
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

    let headers = &["Name", "Runtime", "State", "Url"];
    output.print_table(headers, &rows);
    output.write_table("functions", headers, &rows)?;
    output.write_json("functions", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
