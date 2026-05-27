use anyhow::Result;
use aws_sdk_iam::types::EntityType;
use colored::Colorize;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::aws::client::ClientFactory;
use crate::aws::graph::{build_graph, EdgeKind, Principal};
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct CapeRow {
    #[serde(rename = "ExternalAccount")]
    pub external_account: String,
    #[serde(rename = "EntryRoleArn")]
    pub entry_role_arn: String,
    #[serde(rename = "TargetRoleArn")]
    pub target_role_arn: String,
    #[serde(rename = "ChainLength")]
    pub chain_length: usize,
    #[serde(rename = "ContainsAdmin")]
    pub contains_admin: bool,
}

/// Extract the account ID embedded in an ARN (slot 4, colon-separated).
fn account_of_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.split(':').collect();
    parts.get(4).filter(|s| !s.is_empty()).map(|s| s.to_string())
}

/// Extract the resource name part after the last "/" — e.g. arn:aws:iam::1:role/admin → "admin".
fn role_name_of_arn(arn: &str) -> Option<String> {
    arn.rsplit('/').next().map(|s| s.to_string())
}

/// Decode a percent-encoded string (e.g. IAM inline policy).
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

/// Inspect an inline policy document JSON string and return true if any Allow
/// statement grants `*:*` (admin-equivalent).
fn policy_is_admin(json_str: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let stmts: Vec<serde_json::Value> = match v.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(s) => vec![s.clone()],
        None => return false,
    };
    for stmt in &stmts {
        if stmt
            .get("Effect")
            .and_then(|v| v.as_str())
            .unwrap_or("Allow")
            != "Allow"
        {
            continue;
        }
        let actions: Vec<String> = match stmt.get("Action") {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|i| i.as_str().map(|s| s.to_string()))
                .collect(),
            _ => Vec::new(),
        };
        let resources: Vec<String> = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(a)) => a
                .iter()
                .filter_map(|i| i.as_str().map(|s| s.to_string()))
                .collect(),
            _ => Vec::new(),
        };
        let has_star_action = actions.iter().any(|a| a == "*");
        let has_star_resource = resources.iter().any(|r| r == "*");
        if has_star_action && has_star_resource {
            return true;
        }
    }
    false
}

/// Build a map of role-name -> ContainsAdmin via get_account_authorization_details.
/// Tolerates AccessDenied (returns empty map + warning).
async fn build_admin_map(factory: &ClientFactory) -> HashMap<String, bool> {
    let mut admin_map: HashMap<String, bool> = HashMap::new();
    let iam = factory.iam();

    // First fetch all AWS-managed and customer-managed policies to inspect names + ARNs.
    // We need to walk pages and then for each role, check attached managed policies +
    // inline policies.
    let mut marker: Option<String> = None;
    loop {
        let mut req = iam
            .get_account_authorization_details()
            .filter(EntityType::Role)
            .filter(EntityType::LocalManagedPolicy)
            .filter(EntityType::AwsManagedPolicy);
        if let Some(m) = marker.as_ref() {
            req = req.marker(m.clone());
        }
        let page = match req.send().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} get_account_authorization_details access denied / failed: {}",
                    "[-]".yellow(),
                    e
                );
                return admin_map;
            }
        };

        // Index managed policies by ARN -> is_admin.
        let mut managed_admin: HashMap<String, bool> = HashMap::new();
        for pol in page.policies() {
            let arn = match pol.arn() {
                Some(a) => a.to_string(),
                None => continue,
            };
            let name = pol.policy_name().unwrap_or_default().to_string();
            let mut is_admin = name == "AdministratorAccess";
            if !is_admin {
                // Check the default policy version document.
                if let Some(default_ver) = pol.default_version_id() {
                    for ver in pol.policy_version_list() {
                        if ver.version_id() == Some(default_ver) {
                            if let Some(doc) = ver.document() {
                                let decoded = decode_policy(doc);
                                let s = if decoded.trim_start().starts_with('{') {
                                    decoded
                                } else {
                                    doc.to_string()
                                };
                                if policy_is_admin(&s) {
                                    is_admin = true;
                                }
                            }
                        }
                    }
                }
            }
            managed_admin.insert(arn, is_admin);
        }

        for role in page.role_detail_list() {
            let name = role.role_name().unwrap_or_default().to_string();
            if name.is_empty() {
                continue;
            }
            let mut is_admin = false;

            // Attached managed policies
            for p in role.attached_managed_policies() {
                let arn = p.policy_arn().unwrap_or_default();
                let pname = p.policy_name().unwrap_or_default();
                if pname == "AdministratorAccess" {
                    is_admin = true;
                    break;
                }
                if let Some(&v) = managed_admin.get(arn) {
                    if v {
                        is_admin = true;
                        break;
                    }
                }
            }

            // Inline policies
            if !is_admin {
                for p in role.role_policy_list() {
                    if let Some(doc) = p.policy_document() {
                        let decoded = decode_policy(doc);
                        let s = if decoded.trim_start().starts_with('{') {
                            decoded
                        } else {
                            doc.to_string()
                        };
                        if policy_is_admin(&s) {
                            is_admin = true;
                            break;
                        }
                    }
                }
            }

            admin_map.insert(name, is_admin);
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

    admin_map
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[cape]".cyan().bold());

    // 1. Our account ID
    let our_account = match factory.sts().get_caller_identity().send().await {
        Ok(r) => r.account().unwrap_or_default().to_string(),
        Err(e) => {
            eprintln!("{} sts get_caller_identity failed: {}", "[-]".yellow(), e);
            String::new()
        }
    };
    if our_account.is_empty() {
        eprintln!(
            "{} Cannot determine caller account — external-account check disabled.",
            "[-]".yellow()
        );
    }

    // 2. Build the graph
    let graph = build_graph(factory).await;

    // 3. Find external entry points: role nodes with an incoming CanAssume edge from
    //    an Account principal != our account, OR Wildcard, OR User/Role in foreign account.
    //    Record (external_account_id, role_arn).
    let mut entry_points: Vec<(String, String, NodeIndex)> = Vec::new(); // (external_acct, role_arn, role_node)
    for idx in graph.node_indices() {
        let role_arn = match &graph[idx] {
            Principal::Role(arn) => arn.clone(),
            _ => continue,
        };
        // Only roles in our account count as in-account targets.
        let role_acct = match account_of_arn(&role_arn) {
            Some(a) => a,
            None => continue,
        };
        if !our_account.is_empty() && role_acct != our_account {
            continue;
        }
        for e in graph.edges_directed(idx, Direction::Incoming) {
            if !matches!(e.weight(), EdgeKind::CanAssume) {
                continue;
            }
            let src = &graph[e.source()];
            let external_acct: Option<String> = match src {
                Principal::Wildcard => Some("*".to_string()),
                Principal::Account(acct) => {
                    if our_account.is_empty() || acct != &our_account {
                        Some(acct.clone())
                    } else {
                        None
                    }
                }
                Principal::User(arn) | Principal::Role(arn) => {
                    account_of_arn(arn).and_then(|a| {
                        if our_account.is_empty() || a != our_account {
                            Some(a)
                        } else {
                            None
                        }
                    })
                }
                _ => None,
            };
            if let Some(acct) = external_acct {
                entry_points.push((acct, role_arn.clone(), idx));
            }
        }
    }

    // Deduplicate entry_points (external_acct, role_arn).
    let mut seen: HashSet<(String, String)> = HashSet::new();
    entry_points.retain(|(a, r, _)| seen.insert((a.clone(), r.clone())));

    // 4. Build a map of role-name -> ContainsAdmin (best effort).
    let admin_map = build_admin_map(factory).await;

    // 5. For each entry point, BFS along CanAssume edges to in-account Role nodes.
    //    Build the chain via `parent` map; emit one row per reachable target.
    let mut rows: Vec<CapeRow> = Vec::new();
    let mut chain_texts: Vec<String> = Vec::new();

    for (external_acct, entry_arn, entry_node) in &entry_points {
        // BFS — track parent node for chain reconstruction.
        let mut parent: HashMap<NodeIndex, Option<NodeIndex>> = HashMap::new();
        let mut depth: HashMap<NodeIndex, usize> = HashMap::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        parent.insert(*entry_node, None);
        depth.insert(*entry_node, 1);
        queue.push_back(*entry_node);

        while let Some(curr) = queue.pop_front() {
            let d = *depth.get(&curr).unwrap_or(&1);
            // Outbound CanAssume edges = roles the current role can chain into.
            for e in graph.edges_directed(curr, Direction::Outgoing) {
                if !matches!(e.weight(), EdgeKind::CanAssume) {
                    continue;
                }
                let tgt = e.target();
                if parent.contains_key(&tgt) {
                    continue;
                }
                // Target must be an in-account Role.
                if let Principal::Role(arn) = &graph[tgt] {
                    if let Some(acct) = account_of_arn(arn) {
                        if our_account.is_empty() || acct == our_account {
                            parent.insert(tgt, Some(curr));
                            depth.insert(tgt, d + 1);
                            queue.push_back(tgt);
                        }
                    }
                }
            }
        }

        // Each visited node (including the entry) is a reachable target.
        for (node, _) in &parent {
            let target_arn = match &graph[*node] {
                Principal::Role(arn) => arn.clone(),
                _ => continue,
            };
            let chain_len = *depth.get(node).unwrap_or(&1);
            let contains_admin = role_name_of_arn(&target_arn)
                .and_then(|n| admin_map.get(&n).copied())
                .unwrap_or(false);

            rows.push(CapeRow {
                external_account: external_acct.clone(),
                entry_role_arn: entry_arn.clone(),
                target_role_arn: target_arn.clone(),
                chain_length: chain_len,
                contains_admin,
            });

            // Reconstruct chain for loot.
            let mut chain: Vec<String> = Vec::new();
            let mut cursor: Option<NodeIndex> = Some(*node);
            while let Some(n) = cursor {
                if let Principal::Role(arn) = &graph[n] {
                    chain.push(arn.clone());
                }
                cursor = parent.get(&n).cloned().unwrap_or(None);
            }
            chain.reverse();
            let text = format!(
                "External {} -> {}",
                external_acct,
                chain.join("  ==assume==>  ")
            );
            chain_texts.push(text);
        }
    }

    // Dedupe rows (external_acct + entry + target).
    let mut row_seen: HashSet<(String, String, String)> = HashSet::new();
    rows.retain(|r| {
        row_seen.insert((
            r.external_account.clone(),
            r.entry_role_arn.clone(),
            r.target_role_arn.clone(),
        ))
    });

    // ---------- Output ----------
    let headers = &[
        "ExternalAccount",
        "EntryRoleArn",
        "TargetRoleArn",
        "ChainLength",
        "ContainsAdmin",
    ];

    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.external_account.clone(),
                r.entry_role_arn.clone(),
                r.target_role_arn.clone(),
                r.chain_length.to_string(),
                r.contains_admin.to_string(),
            ]
        })
        .collect();

    if rows.is_empty() {
        println!("No cross-account privilege escalation paths found.");
    } else {
        output.print_table(headers, &table_rows);
    }

    output.write_table("cape", headers, &table_rows)?;
    output.write_csv("cape", &rows)?;
    output.write_json("cape", &rows)?;

    // Loot: chains.txt
    let mut chains_body = String::new();
    chains_body.push_str("# CAPE — Cross-Account Privilege Escalation Chains\n\n");
    if chain_texts.is_empty() {
        chains_body.push_str("(none discovered)\n");
    } else {
        for line in &chain_texts {
            chains_body.push_str(line);
            chains_body.push('\n');
        }
    }
    output.loot_file("cape", "chains.txt", chains_body.as_bytes())?;

    // Loot: external-entry-points.txt
    let mut entry_body = String::new();
    entry_body.push_str("# CAPE — External Entry Points\n\n");
    entry_body.push_str("ExternalAccount\tEntryRoleArn\n");
    let mut entry_dedupe: HashSet<(String, String)> = HashSet::new();
    for (acct, arn, _) in &entry_points {
        if entry_dedupe.insert((acct.clone(), arn.clone())) {
            entry_body.push_str(&format!("{}\t{}\n", acct, arn));
        }
    }
    output.loot_file("cape", "external-entry-points.txt", entry_body.as_bytes())?;

    let admin_count = rows.iter().filter(|r| r.contains_admin).count();
    if admin_count > 0 {
        println!(
            "{} {} chain(s) terminate at admin-equivalent roles",
            "[!]".red().bold(),
            admin_count
        );
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
