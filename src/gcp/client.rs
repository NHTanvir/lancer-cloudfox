use anyhow::{Context, Result};
use std::process::Command;

pub struct GcpClient {
    pub project: String,
    pub access_token: String,
    pub http: reqwest::Client,
}

impl GcpClient {
    pub fn new(project: Option<String>) -> Result<Self> {
        let out = Command::new("gcloud")
            .args(["auth", "print-access-token"])
            .output()
            .context("Failed to invoke `gcloud`. Install: https://cloud.google.com/sdk/docs/install")?;
        if !out.status.success() {
            anyhow::bail!("`gcloud auth print-access-token` failed. Run `gcloud auth login` first.");
        }
        let access_token = String::from_utf8(out.stdout)?.trim().to_string();

        let project = match project {
            Some(p) => p,
            None => {
                let out = Command::new("gcloud")
                    .args(["config", "get-value", "project"])
                    .output()
                    .context("Failed to invoke `gcloud`")?;
                let p = String::from_utf8(out.stdout)?.trim().to_string();
                if p.is_empty() {
                    anyhow::bail!("No project set. Use --project or `gcloud config set project <id>`.");
                }
                p
            }
        };

        Ok(Self {
            project,
            access_token,
            http: reqwest::Client::new(),
        })
    }
}
