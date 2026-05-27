use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct GcpArgs {
    #[arg(long, short = 'p', global = true, help = "GCP project ID")]
    pub project: Option<String>,

    #[arg(long, global = true, help = "Max concurrent API calls", default_value = "10")]
    pub concurrency: usize,

    #[command(subcommand)]
    pub command: GcpCommand,
}

#[derive(Subcommand, Debug)]
pub enum GcpCommand {
    #[command(about = "Show current GCP identity")]
    Whoami,

    #[command(about = "Resource inventory across the project")]
    Inventory,

    #[command(about = "Project-level IAM policy")]
    Iam,

    #[command(about = "Enumerate service accounts + keys")]
    Serviceaccounts,

    #[command(about = "Detect IAM privesc paths")]
    Privesc,

    #[command(about = "Cloud Storage buckets + IAM/policy")]
    Storage,

    #[command(about = "GKE clusters")]
    Gke,

    #[command(about = "Compute Engine instances")]
    Instances,

    #[command(about = "Cloud Functions")]
    Functions,

    #[command(about = "Cloud Run services")]
    Cloudrun,

    #[command(about = "Secret Manager secrets (metadata only)")]
    Secrets,

    #[command(about = "BigQuery datasets and tables")]
    Bigquery,

    #[command(about = "Cloud SQL instances")]
    Cloudsql,

    #[command(about = "KMS keyrings + crypto keys + IAM")]
    Kms,
}
