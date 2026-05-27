use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

/// Curated set of high-impact actions to simulate against every principal.
/// Same flavour CloudFox uses to flag dangerous privileges.
const HIGH_IMPACT_ACTIONS: &[&str] = &[
    "sts:AssumeRole",
    "iam:PassRole",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:SendCommand",
    "s3:ListBucket",
    "s3:GetObject",
    "ecr:BatchGetImage",
    "lambda:ListFunctions",
    "eks:UpdateClusterConfig",
    "sns:Subscribe",
    "sqs:SendMessage",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
];

/// IAM SimulatePrincipalPolicy hard-limits ActionNames to 50 per request.
const ACTIONS_PER_CALL: usize = 50;

#[derive(Serialize, Clone)]
pub struct SimulationRow {
    pub principal_arn: String,
    pub action: String,
    pub decision: String,
    pub matched_statements_count: usize,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[iam-simulator]".cyan().bold());

    let iam = factory.iam();

    // Collect every IAM principal ARN (users + roles)
    let mut principals: Vec<(String, String)> = Vec::new(); // (kind, arn)

    let mut user_pages = iam.list_users().into_paginator().send();
    while let Some(page) = user_pages.next().await {
        match page {
            Ok(p) => {
                for u in p.users() {
                    principals.push(("User".to_string(), u.arn().to_string()));
                }
            }
            Err(e) => {
                eprintln!(
                    "{} list_users failed: {}",
                    "[-]".yellow(),
                    e.into_service_error()
                );
                return Ok(());
            }
        }
    }

    let mut role_pages = iam.list_roles().into_paginator().send();
    while let Some(page) = role_pages.next().await {
        match page {
            Ok(p) => {
                for r in p.roles() {
                    principals.push(("Role".to_string(), r.arn().to_string()));
                }
            }
            Err(e) => {
                eprintln!(
                    "{} list_roles failed: {}",
                    "[-]".yellow(),
                    e.into_service_error()
                );
                return Ok(());
            }
        }
    }

    if principals.is_empty() {
        println!("No IAM principals found (or insufficient permissions).");
        return Ok(());
    }

    let mut rows: Vec<SimulationRow> = Vec::new();
    let action_chunks: Vec<&[&str]> = HIGH_IMPACT_ACTIONS.chunks(ACTIONS_PER_CALL).collect();

    let mut access_denied = false;

    for (_kind, arn) in &principals {
        for chunk in &action_chunks {
            let mut req = iam.simulate_principal_policy().policy_source_arn(arn);
            for action in chunk.iter() {
                req = req.action_names(action.to_string());
            }

            match req.send().await {
                Ok(resp) => {
                    for result in resp.evaluation_results() {
                        rows.push(SimulationRow {
                            principal_arn: arn.clone(),
                            action: result.eval_action_name().to_string(),
                            decision: result.eval_decision().as_str().to_string(),
                            matched_statements_count: result.matched_statements().len(),
                        });
                    }
                }
                Err(e) => {
                    let svc = e.into_service_error();
                    let msg = format!("{svc}");
                    if msg.contains("AccessDenied") || msg.contains("not authorized") {
                        access_denied = true;
                        eprintln!(
                            "{} Caller lacks iam:SimulatePrincipalPolicy. Cannot continue.",
                            "[-]".yellow().bold()
                        );
                        break;
                    } else {
                        eprintln!(
                            "{} simulate_principal_policy({}) failed: {}",
                            "[-]".yellow(),
                            arn,
                            msg
                        );
                    }
                }
            }
        }
        if access_denied {
            break;
        }
    }

    if access_denied {
        return Ok(());
    }

    if rows.is_empty() {
        println!("No simulation results produced.");
        return Ok(());
    }

    // Display: only show Allowed rows in the terminal table (least noise),
    // but persist every row to disk.
    let display_rows: Vec<Vec<String>> = rows
        .iter()
        .filter(|r| r.decision == "allowed")
        .map(|r| vec![r.principal_arn.clone(), r.action.clone(), r.decision.clone()])
        .collect();

    let headers = &["PrincipalArn", "Action", "Decision"];
    if display_rows.is_empty() {
        println!("No 'allowed' results in simulation (every action denied).");
    } else {
        output.print_table(headers, &display_rows);
    }

    let all_display: Vec<Vec<String>> = rows
        .iter()
        .map(|r| vec![r.principal_arn.clone(), r.action.clone(), r.decision.clone()])
        .collect();

    output.write_table("iam-simulator", headers, &all_display)?;
    output.write_csv("iam-simulator", &rows)?;
    output.write_json("iam-simulator", &rows)?;

    // Pull account id once for the pmapper hint
    let account_id = factory
        .sts()
        .get_caller_identity()
        .send()
        .await
        .ok()
        .and_then(|r| r.account().map(|s| s.to_string()))
        .unwrap_or_else(|| "<account-id>".to_string());

    let mut loot = String::new();
    loot.push_str("# Follow-up commands for IAM simulator results\n");
    loot.push_str("# pmapper is the canonical tool for graphing IAM trust + privilege escalation.\n\n");
    loot.push_str(&format!(
        "pmapper --profile {} graph create\n",
        factory.profile
    ));
    loot.push_str(&format!(
        "pmapper --profile {} graph display\n",
        factory.profile
    ));
    loot.push_str(&format!(
        "pmapper --profile {} query 'preset privesc *'\n",
        factory.profile
    ));
    loot.push_str(&format!(
        "pmapper --profile {} graph create --account {}\n",
        factory.profile, account_id
    ));
    loot.push_str("\n# Per-principal targeted simulations (re-run with a single principal):\n");
    for (_kind, arn) in &principals {
        loot.push_str(&format!(
            "aws --profile {} iam simulate-principal-policy --policy-source-arn {} --action-names {}\n",
            factory.profile,
            arn,
            HIGH_IMPACT_ACTIONS.join(" ")
        ));
    }
    output.loot_commands("iam-simulator-pmapper-commands", &loot)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
