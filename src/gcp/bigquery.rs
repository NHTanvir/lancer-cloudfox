use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:bigquery]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!(
        "https://bigquery.googleapis.com/bigquery/v2/projects/{}/datasets",
        client.project
    );
    let mut url = base.clone();
    let mut datasets: Vec<String> = vec![];
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
        if let Some(items) = body.get("datasets").and_then(|v| v.as_array()) {
            for it in items {
                if let Some(ds_id) = it
                    .get("datasetReference")
                    .and_then(|v| v.get("datasetId"))
                    .and_then(|v| v.as_str())
                {
                    datasets.push(ds_id.to_string());
                }
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

    // For each dataset, list tables
    for ds in &datasets {
        let tables_base = format!(
            "https://bigquery.googleapis.com/bigquery/v2/projects/{}/datasets/{}/tables",
            client.project, ds
        );
        let mut t_url = tables_base.clone();
        loop {
            let resp = client
                .http
                .get(&t_url)
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
            if let Some(items) = body.get("tables").and_then(|v| v.as_array()) {
                for it in items {
                    let tid = it
                        .get("tableReference")
                        .and_then(|v| v.get("tableId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ttype = it
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("TABLE")
                        .to_string();
                    let created = it
                        .get("creationTime")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    rows.push(vec![ds.clone(), tid, ttype, created]);
                    json_data.push(it.clone());
                }
            }
            match body.get("nextPageToken").and_then(|v| v.as_str()) {
                Some(t) if !t.is_empty() => {
                    t_url = format!("{}?pageToken={}", tables_base, t);
                }
                _ => break,
            }
        }
    }

    let headers = &["Dataset", "Table", "Type", "Created"];
    output.print_table(headers, &rows);
    output.write_table("bigquery", headers, &rows)?;
    output.write_json("bigquery", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
