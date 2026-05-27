use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

/// Internal concurrency cap when probing each bucket's metadata.
const PER_BUCKET_CONCURRENCY: usize = 20;

/// AWS S3 well-known group URIs that flag a bucket as "public" via ACL grant.
const PUBLIC_GROUP_URIS: &[&str] = &[
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
];

#[derive(Serialize, Clone)]
pub struct BucketRow {
    pub bucket: String,
    pub region: String,
    pub public: bool,
    pub encrypted: bool,
    pub versioning: String,
    pub policy_exists: bool,
    pub acl_grants: Vec<String>,
    pub policy: Option<String>,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[buckets]".cyan().bold());

    let s3_global = factory.s3();

    let list_resp = match s3_global.list_buckets().send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} list_buckets failed: {}",
                "[-]".yellow(),
                e.into_service_error()
            );
            return Ok(());
        }
    };

    let bucket_names: Vec<String> = list_resp
        .buckets()
        .iter()
        .filter_map(|b| b.name().map(|n| n.to_string()))
        .collect();

    if bucket_names.is_empty() {
        println!("No S3 buckets found.");
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(PER_BUCKET_CONCURRENCY));
    let factory = Arc::new(factory.clone());

    let mut handles = Vec::with_capacity(bucket_names.len());
    for bucket in bucket_names {
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            inspect_bucket(&factory, bucket).await
        }));
    }

    let mut rows: Vec<BucketRow> = Vec::new();
    for h in handles {
        if let Ok(row) = h.await {
            rows.push(row);
        }
    }

    // Sort for stable output.
    rows.sort_by(|a, b| a.bucket.cmp(&b.bucket));

    let display_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.bucket.clone(),
                r.region.clone(),
                yn(r.public),
                yn(r.encrypted),
                r.versioning.clone(),
                yn(r.policy_exists),
            ]
        })
        .collect();

    let headers = &[
        "Bucket",
        "Region",
        "Public?",
        "Encrypted?",
        "Versioning",
        "PolicyExists",
    ];

    output.print_table(headers, &display_rows);
    output.write_table("buckets", headers, &display_rows)?;
    output.write_csv("buckets", &rows)?;
    output.write_json("buckets", &rows)?;

    // Dump raw policy JSON per bucket into loot/bucket-policies/
    for r in &rows {
        if let Some(p) = &r.policy {
            // Pretty-print if it parses, otherwise dump raw.
            let body = match serde_json::from_str::<serde_json::Value>(p) {
                Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| p.clone()),
                Err(_) => p.clone(),
            };
            output.loot_file(
                "bucket-policies",
                &format!("{}.json", r.bucket),
                body.as_bytes(),
            )?;
        }
    }

    // Loot commands: useful follow-ups per bucket.
    let mut loot = String::new();
    loot.push_str("# AWS CLI follow-ups for each discovered bucket\n\n");
    for r in &rows {
        loot.push_str(&format!("# === {} ({}) ===\n", r.bucket, r.region));
        loot.push_str(&format!(
            "aws --profile {} --region {} s3api list-objects-v2 --bucket {} --max-items 50\n",
            factory.profile, r.region, r.bucket
        ));
        loot.push_str(&format!(
            "aws --profile {} --region {} s3api get-bucket-policy --bucket {}\n",
            factory.profile, r.region, r.bucket
        ));
        loot.push_str(&format!(
            "aws --profile {} --region {} s3api get-bucket-acl --bucket {}\n",
            factory.profile, r.region, r.bucket
        ));
        loot.push_str(&format!(
            "aws --profile {} s3 sync s3://{}/ ./loot-{}/ --no-sign-request   # try anonymous\n",
            factory.profile, r.bucket, r.bucket
        ));
        loot.push('\n');
    }
    output.loot_commands("bucket-commands", &loot)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}

fn yn(b: bool) -> String {
    if b { "yes".to_string() } else { "no".to_string() }
}

async fn inspect_bucket(factory: &ClientFactory, bucket: String) -> BucketRow {
    // 1. Region — call the global client; S3 redirects fine for get_bucket_location.
    let s3_global = factory.s3();
    let region = match s3_global.get_bucket_location().bucket(&bucket).send().await {
        Ok(r) => location_to_region(r.location_constraint().map(|lc| lc.as_str())),
        Err(_) => "us-east-1".to_string(),
    };

    // Build a region-pinned client for the remaining calls.
    let s3 = {
        let conf = aws_sdk_s3::config::Builder::from(&factory.config)
            .region(aws_sdk_s3::config::Region::new(region.clone()))
            .build();
        aws_sdk_s3::Client::from_conf(conf)
    };

    // 2. ACL grants
    let mut acl_grants: Vec<String> = Vec::new();
    let mut public_via_acl = false;
    if let Ok(acl) = s3.get_bucket_acl().bucket(&bucket).send().await {
        for g in acl.grants() {
            let perm = g.permission().map(|p| p.as_str()).unwrap_or("?").to_string();
            let grantee = g.grantee();
            let label = if let Some(gr) = grantee {
                if let Some(uri) = gr.uri() {
                    if PUBLIC_GROUP_URIS.contains(&uri) {
                        public_via_acl = true;
                    }
                    format!("Group({uri})")
                } else if let Some(id) = gr.id() {
                    format!("CanonicalUser({id})")
                } else if let Some(dn) = gr.display_name() {
                    format!("DisplayName({dn})")
                } else {
                    "Unknown".to_string()
                }
            } else {
                "Unknown".to_string()
            };
            acl_grants.push(format!("{label}={perm}"));
        }
    }

    // 3. Policy (NoSuchBucketPolicy -> None)
    let policy = match s3.get_bucket_policy().bucket(&bucket).send().await {
        Ok(p) => p.policy().map(|s| s.to_string()),
        Err(_) => None,
    };

    // 4. Public access block
    let mut pab_locked = false;
    if let Ok(pab) = s3.get_public_access_block().bucket(&bucket).send().await {
        if let Some(cfg) = pab.public_access_block_configuration() {
            // Treat as "locked down" only when all four flags are true.
            pab_locked = cfg.block_public_acls().unwrap_or(false)
                && cfg.block_public_policy().unwrap_or(false)
                && cfg.ignore_public_acls().unwrap_or(false)
                && cfg.restrict_public_buckets().unwrap_or(false);
        }
    }

    // A bucket is "public" if either an ACL grant exposes it OR a policy exists
    // and PAB is not fully locking the bucket down.
    let public = (public_via_acl || policy.is_some()) && !pab_locked;

    // 5. Encryption
    let encrypted = matches!(
        s3.get_bucket_encryption().bucket(&bucket).send().await,
        Ok(resp) if resp
            .server_side_encryption_configuration()
            .map(|c| !c.rules().is_empty())
            .unwrap_or(false)
    );

    // 6. Versioning
    let versioning = match s3.get_bucket_versioning().bucket(&bucket).send().await {
        Ok(v) => v
            .status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "Disabled".to_string()),
        Err(_) => "Unknown".to_string(),
    };

    BucketRow {
        bucket,
        region,
        public,
        encrypted,
        versioning,
        policy_exists: policy.is_some(),
        acl_grants,
        policy,
    }
}

fn location_to_region(lc: Option<&str>) -> String {
    match lc {
        None | Some("") | Some("null") => "us-east-1".to_string(),
        Some("EU") => "eu-west-1".to_string(),
        Some(other) => other.to_string(),
    }
}
