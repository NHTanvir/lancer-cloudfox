use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use super::client::GcpClient;
use crate::output::OutputWriter;

pub async fn run(client: &GcpClient, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[gcp:instances]".cyan().bold());
    let auth = format!("Bearer {}", client.access_token);

    let mut rows: Vec<Vec<String>> = vec![];
    let mut json_data: Vec<Value> = vec![];

    let base = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/instances",
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
        if let Some(map) = body.get("items").and_then(|v| v.as_object()) {
            for (zone_key, zone_val) in map {
                let zone_short = zone_key.trim_start_matches("zones/").to_string();
                if let Some(insts) = zone_val.get("instances").and_then(|v| v.as_array()) {
                    for inst in insts {
                        let name = inst
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let machine_type = inst
                            .get("machineType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        let status = inst
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        // external IP
                        let mut ext_ip = String::new();
                        if let Some(nics) =
                            inst.get("networkInterfaces").and_then(|v| v.as_array())
                        {
                            for nic in nics {
                                if let Some(accs) =
                                    nic.get("accessConfigs").and_then(|v| v.as_array())
                                {
                                    for ac in accs {
                                        if let Some(ip) =
                                            ac.get("natIP").and_then(|v| v.as_str())
                                        {
                                            if !ip.is_empty() {
                                                ext_ip = ip.to_string();
                                                break;
                                            }
                                        }
                                    }
                                }
                                if !ext_ip.is_empty() {
                                    break;
                                }
                            }
                        }
                        rows.push(vec![
                            zone_short.clone(),
                            name,
                            machine_type,
                            status,
                            ext_ip,
                        ]);
                        json_data.push(inst.clone());
                    }
                }
            }
        }
        match body.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => {
                let sep = if base.contains('?') { "&" } else { "?" };
                url = format!("{}{}pageToken={}", base, sep, t);
            }
            _ => break,
        }
    }

    let headers = &["Zone", "Name", "MachineType", "Status", "ExternalIp"];
    output.print_table(headers, &rows);
    output.write_table("instances", headers, &rows)?;
    output.write_json("instances", &json_data)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
