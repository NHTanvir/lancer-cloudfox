use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:serviceaccounts]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base_url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts",
        client.project
    );
    let mut url = base_url.clone();
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
        if let Some(items) = body.get("accounts").and_then(|v| v.as_array()) {
            for it in items {
                let email = it
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display = it
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let disabled = it
                    .get("disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let name = it.get("name").and_then(|v| v.as_str()).unwrap_or("");

                // fetch keys
                let mut key_count: usize = 0;
                if !name.is_empty() {
                    let keys_url = format!("https://iam.googleapis.com/v1/{}/keys", name);
                    if let Ok(kresp) = client
                        .http
                        .get(&keys_url)
                        .header("Authorization", &auth)
                        .send()
                        .await
                    {
                        if kresp.status().is_success() {
                            if let Ok(kbody) = kresp.json::<Value>().await {
                                if let Some(keys) =
                                    kbody.get("keys").and_then(|v| v.as_array())
                                {
                                    key_count = keys.len();
                                }
                            }
                        }
                    }
                }

                rows.push(vec![
                    email,
                    display,
                    key_count.to_string(),
                    disabled.to_string(),
                ]);
                json_data.push(it.clone());
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                url = format!("{}?pageToken={}", base_url, t);
            }
            _ => break,
        }
    }

    let headers = &["Email", "DisplayName", "KeyCount", "Disabled"];
    output.print_table(headers, &rows);
    output.write_table("serviceaccounts", headers, &rows)?;
    output.write_json("serviceaccounts", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
