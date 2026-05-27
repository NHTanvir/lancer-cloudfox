use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct Route53Row {
    pub zone_name: String,
    pub zone_id: String,
    pub record_name: String,
    pub record_type: String,
    pub ttl: String,
    pub value: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[route53]".cyan().bold());
    let client = factory.route53();
    let mut all_rows: Vec<Route53Row> = vec![];

    let mut zone_paginator = client.list_hosted_zones().into_paginator().send();
    let mut zones: Vec<(String, String)> = vec![]; // (zone_id, zone_name)
    while let Some(page) = zone_paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(_) => break,
        };
        for z in page.hosted_zones() {
            let id = z.id().to_string();
            let name = z.name().to_string();
            zones.push((id, name));
        }
    }

    for (zone_id, zone_name) in &zones {
        let mut zone_rows: Vec<Route53Row> = vec![];
        let bare_id = zone_id.trim_start_matches("/hostedzone/").to_string();

        // list_resource_record_sets has no SDK paginator; loop on
        // is_truncated + next_record_name / next_record_type / next_record_identifier.
        let mut start_name: Option<String> = None;
        let mut start_type: Option<aws_sdk_route53::types::RrType> = None;
        let mut start_identifier: Option<String> = None;
        loop {
            let mut req = client.list_resource_record_sets().hosted_zone_id(&bare_id);
            if let Some(n) = start_name.clone() {
                req = req.start_record_name(n);
            }
            if let Some(t) = start_type.clone() {
                req = req.start_record_type(t);
            }
            if let Some(i) = start_identifier.clone() {
                req = req.start_record_identifier(i);
            }
            let page = match req.send().await {
                Ok(p) => p,
                Err(_) => break,
            };
            for rr in page.resource_record_sets() {
                let rname = rr.name().to_string();
                let rtype = rr.r#type().as_str().to_string();
                let ttl = rr.ttl().map(|t| t.to_string()).unwrap_or_default();
                let values: Vec<String> = rr
                    .resource_records()
                    .iter()
                    .map(|v| v.value().to_string())
                    .collect();
                let alias_value = rr
                    .alias_target()
                    .map(|a| format!("ALIAS:{}", a.dns_name()))
                    .unwrap_or_default();
                if values.is_empty() && !alias_value.is_empty() {
                    zone_rows.push(Route53Row {
                        zone_name: zone_name.clone(),
                        zone_id: bare_id.clone(),
                        record_name: rname.clone(),
                        record_type: rtype.clone(),
                        ttl: ttl.clone(),
                        value: alias_value,
                    });
                } else {
                    for v in values {
                        zone_rows.push(Route53Row {
                            zone_name: zone_name.clone(),
                            zone_id: bare_id.clone(),
                            record_name: rname.clone(),
                            record_type: rtype.clone(),
                            ttl: ttl.clone(),
                            value: v,
                        });
                    }
                }
            }
            if !page.is_truncated() {
                break;
            }
            start_name = page.next_record_name().map(|s| s.to_string());
            start_type = page.next_record_type().cloned();
            start_identifier = page.next_record_identifier().map(|s| s.to_string());
        }
        // Loot dump per zone
        let mut body = String::new();
        for r in &zone_rows {
            body.push_str(&format!(
                "{} {} {} {} {}\n",
                r.record_name, r.record_type, r.ttl, r.zone_id, r.value
            ));
        }
        let safe_name = zone_name.trim_end_matches('.').replace('/', "_");
        output.loot_file("route53", &format!("{}.txt", safe_name), body)?;
        all_rows.extend(zone_rows);
    }

    let headers = &["ZoneName", "ZoneId", "RecordName", "Type", "TTL", "Value"];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.zone_name.clone(),
                r.zone_id.clone(),
                r.record_name.clone(),
                r.record_type.clone(),
                r.ttl.clone(),
                r.value.clone(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("route53", headers, &display)?;
    output.write_csv("route53", &all_rows)?;
    output.write_json("route53", &all_rows)?;
    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
