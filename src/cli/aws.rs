use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct AwsArgs {
    #[arg(long, short = 'p', global = true, help = "AWS profile name")]
    pub profile: Option<String>,

    #[arg(long, short = 'r', global = true, help = "Comma-separated list of regions (default: us-east-1)")]
    pub regions: Option<String>,

    #[arg(long, global = true, help = "Max concurrent API calls", default_value = "10")]
    pub concurrency: usize,

    #[arg(long, global = true, help = "Output directory prefix")]
    pub output: Option<String>,

    #[command(subcommand)]
    pub command: AwsCommand,
}

#[derive(Subcommand, Debug)]
pub enum AwsCommand {
    #[command(about = "Show current AWS identity (sts:GetCallerIdentity)")]
    Whoami,

    #[command(about = "Multi-region resource count inventory")]
    Inventory,

    // Week 2 — IAM enumeration
    #[command(about = "List IAM users, roles, and groups")]
    Principals,

    #[command(about = "Enumerate IAM permissions via GetAccountAuthorizationDetails")]
    Permissions,

    // Week 3 — trust policies
    #[command(about = "Parse IAM role trust policies, surface trusted principals")]
    RoleTrusts,

    #[command(about = "Parse resource policies (S3/SNS/SQS/Lambda/Secrets) for external trust")]
    ResourceTrusts,

    // Week 4 — IAM simulator
    #[command(about = "Simulate IAM permissions for high-impact actions per principal")]
    IamSimulator,

    // Week 5 — secret hunting
    #[command(about = "Enumerate S3 buckets with policy / encryption / public-access state")]
    Buckets,

    #[command(about = "List Secrets Manager + SSM Parameter Store metadata (no values)")]
    Secrets,

    #[command(about = "Extract env vars from Lambda / ECS task defs / CodeBuild")]
    EnvVars,

    // Week 6 — compute & network
    #[command(about = "EC2 instances with IAM profile + public IP")]
    Instances,

    #[command(about = "Security-group derived {host:port:source-cidr} matrix")]
    NetworkPorts,

    #[command(about = "Lambda functions with runtime / role / env var count")]
    Lambda,

    #[command(about = "RDS + DynamoDB summary")]
    Databases,

    // Week 7 — infra
    #[command(about = "Route53 hosted zones and record sets")]
    Route53,

    #[command(about = "CloudFormation stacks and outputs")]
    Cloudformation,

    #[command(about = "EKS clusters + node groups + endpoint visibility")]
    Eks,

    #[command(about = "ECR repositories + image counts + repo policies")]
    Ecr,

    #[command(about = "Build trust graph (petgraph) — output DOT/GraphML")]
    Graph,

    #[command(about = "Cross-Account Privilege Escalation enumeration")]
    Cape,

    // Week 12 — aggregate + TUI
    #[command(about = "Run every read-only AWS subcommand sequentially")]
    AllChecks,

    #[command(about = "Interactive TUI viewer for the cape attack-chain results (ratatui)")]
    CapeTui,
}
