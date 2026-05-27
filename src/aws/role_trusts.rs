use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct TrustRow {
    #[serde(rename = "RoleName")]
    pub role_name: String,
    #[serde(rename = "TrustedEntity")]
    pub trusted_entity: String,
    #[serde(rename = "EntityType")]
    pub entity_type: String,
    #[serde(rename = "HasCondition")]
    pub has_condition: bool,
    #[serde(rename = "Flagged")]
    pub flagged: bool,
    #[serde(rename = "FlagReason")]
    pub flag_reason: String,
}

/// Decode a percent-encoded string (e.g. `assume_role_policy_document`).
fn decode_policy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Classify a principal value as (entity_type, raw_value).
fn classify_principal(kind: &str, value: &str) -> (String, String) {
    let v = value.trim().to_string();
    if v == "*" {
        return ("Wildcard".to_string(), v);
    }
    let et = match kind {
        "Service" => "Service".to_string(),
        "Federated" => "Federated".to_string(),
        "CanonicalUser" => "CanonicalUser".to_string(),
        "AWS" | "" => {
            if v.starts_with("arn:aws:iam::") && v.ends_with(":root") {
                "AccountID".to_string()
            } else if v.contains(":user/") {
                "UserARN".to_string()
            } else if v.contains(":role/") {
                "RoleARN".to_string()
            } else if v.chars().all(|c| c.is_ascii_digit()) && v.len() == 12 {
                "AccountID".to_string()
            } else if v == "*" {
                "Wildcard".to_string()
            } else {
                "AWS".to_string()
            }
        }
        other => other.to_string(),
    };
    (et, v)
}

/// Pull a Vec<String> from a serde_json::Value that may be a String, an Array,
/// or null/missing.
fn as_string_vec(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

/// Process one Statement element and append rows.
fn process_statement(role_name: &str, stmt: &Value, rows: &mut Vec<TrustRow>) {
    // Only Effect=Allow are interesting for trust
    if stmt.get("Effect").and_then(|v| v.as_str()).unwrap_or("Allow") != "Allow" {
        return;
    }
    let has_condition = stmt.get("Condition").is_some();
    let condition = stmt.get("Condition").cloned().unwrap_or(Value::Null);

    let principal = match stmt.get("Principal") {
        Some(p) => p.clone(),
        None => return,
    };

    let mut entries: Vec<(String, String)> = Vec::new();

    match &principal {
        Value::String(s) => {
            entries.push(("AWS".to_string(), s.clone()));
        }
        Value::Object(map) => {
            for (k, v) in map.iter() {
                for raw in as_string_vec(v) {
                    entries.push((k.clone(), raw));
                }
            }
        }
        _ => {}
    }

    for (kind, raw) in entries {
        let (entity_type, value) = classify_principal(&kind, &raw);
        let mut flagged = false;
        let mut flag_reason = String::new();

        if entity_type == "Wildcard" {
            flagged = true;
            flag_reason = "wildcard principal".to_string();
            // Check if mitigated by aws:PrincipalOrgID condition
            if has_condition {
                let cond_str = condition.to_string();
                if cond_str.contains("aws:PrincipalOrgID") {
                    flag_reason = "wildcard principal (scoped by aws:PrincipalOrgID)".to_string();
                }
            }
        } else if !has_condition && (entity_type == "AccountID" || entity_type == "AWS") {
            flagged = true;
            flag_reason = "trust without Condition".to_string();
        }

        rows.push(TrustRow {
            role_name: role_name.to_string(),
            trusted_entity: value,
            entity_type,
            has_condition,
            flagged,
            flag_reason,
        });
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[role-trusts]".cyan().bold());

    let iam = factory.iam();
    let mut rows: Vec<TrustRow> = Vec::new();
    // role_name -> Vec<trusted entity strings>
    let mut by_role: Vec<(String, Vec<String>)> = Vec::new();

    let mut paginator = iam.list_roles().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} list_roles failed: {}", "[-]".yellow(), e);
                break;
            }
        };

        for role in page.roles() {
            let role_name = role.role_name().to_string();
            let raw = match role.assume_role_policy_document() {
                Some(s) => s.to_string(),
                None => continue,
            };

            // The SDK returns the policy document URL-encoded; decode it.
            let decoded = decode_policy(&raw);
            // If the decoded string is still not JSON, fall back to raw.
            let json_str = if decoded.trim_start().starts_with('{') {
                decoded
            } else {
                raw
            };

            // Persist raw decoded policy
            let _ = output.loot_file(
                "role-trust-policies",
                &format!("{}.json", sanitize(&role_name)),
                json_str.as_bytes(),
            );

            let value: Value = match serde_json::from_str(&json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "{} failed to parse trust policy for {}: {}",
                        "[-]".yellow(),
                        role_name,
                        e
                    );
                    continue;
                }
            };

            let before = rows.len();

            match value.get("Statement") {
                Some(Value::Array(stmts)) => {
                    for stmt in stmts {
                        process_statement(&role_name, stmt, &mut rows);
                    }
                }
                Some(Value::Object(_)) => {
                    process_statement(&role_name, value.get("Statement").unwrap(), &mut rows);
                }
                _ => {}
            }

            let trusted: Vec<String> = rows[before..]
                .iter()
                .map(|r| format!("{} ({})", r.trusted_entity, r.entity_type))
                .collect();
            by_role.push((role_name, trusted));
        }
    }

    if rows.is_empty() {
        println!("No role trust policies found (or insufficient permissions).");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.role_name.clone(),
                r.trusted_entity.clone(),
                r.entity_type.clone(),
                r.has_condition.to_string(),
            ]
        })
        .collect();

    let headers = &["RoleName", "TrustedEntity", "EntityType", "HasCondition"];
    output.print_table(headers, &table_rows);
    output.write_table("role-trusts", headers, &table_rows)?;
    output.write_csv("role-trusts", &rows)?;
    output.write_json("role-trusts", &rows)?;

    // Loot commands file listing role -> trusted principals
    let mut loot = String::new();
    loot.push_str("# Role -> Principals That Can Assume It\n");
    for (role, principals) in &by_role {
        loot.push_str(&format!("\n## {}\n", role));
        if principals.is_empty() {
            loot.push_str("  (no trusted principals parsed)\n");
        } else {
            for p in principals {
                loot.push_str(&format!("  - {}\n", p));
            }
        }
    }
    output.loot_commands("role-trusts-PrincipalsThatCanAssumeRoles", &loot)?;

    // Highlight flagged
    let flagged_count = rows.iter().filter(|r| r.flagged).count();
    if flagged_count > 0 {
        println!(
            "{} {} flagged trust(s) (wildcard or missing condition)",
            "[!]".yellow().bold(),
            flagged_count
        );
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
