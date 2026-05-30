# RESEARCH DOSSIER: CloudFox

> Part of the Lancer ecosystem. A Rust clone of Bishop Fox's CloudFox — cloud situational awareness for pentests. Build with Claude Code.
> Upstream: github.com/BishopFox/cloudfox (Go, ~120 subcommands AWS/Azure/GCP). v2.0 (2025) added 60+ GCP subcommands.
>
> READ-ONLY by design — no API call should ever modify cloud state.

## Feature Parity Mandate

**`lancer-cloudfox` MUST ship with 100% feature parity to the upstream `cloudfox` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `cloudfox --help` (and the long-form man page / docs) must work in `lancer-cloudfox --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-cloudfox` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-cloudfox --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

CloudFox is Bishop Fox's **situational-awareness** tool for cloud pentests. Where Prowler audits, Pacu attacks, CloudFox just helps you *understand what's there fast*. It answers offensive-team questions: "which IAM roles can be assumed cross-account?", "which Lambda functions are invokable from the internet?", "which secrets are exposed in env vars?", "what's the shortest privesc path from principal X to admin?". Output is **terminal tables + loot files** — JSON, txt, CSV reusable by other tools (especially `pmapper`). Written in **Go**, ~99% Go codebase, ~120 subcommands across AWS/Azure/GCP.

## Internal architecture

```
cloudfox/
  main.go                    # cobra root
  cli/                       # subcommand definitions (aws.go, azure.go, gcp.go)
  aws/                       # per-command modules
    access-keys.go
    api-gws.go
    buckets.go
    cape.go cape-tui.go      # Cross-Account Privesc Enumeration
    client-initializers.go   # AWS SDK v2 setup
    cloudformation.go
    codebuild.go
    databases.go             # RDS, DynamoDB, Redshift
    directory-services.go
    ecr.go ecs-tasks.go eks.go
    elastic-network-interfaces.go
    endpoints.go env-vars.go
    filesystems.go
    graph.go                 # role-trust / resource-trust graph builder
    iam-simulator.go         # uses iam:SimulatePrincipalPolicy
    instances.go             # EC2
    inventory.go             # multi-region resource counts
    lambda.go
    network-ports.go         # SG-derived open-port matrix
    org.go
    outbound-assumed-roles.go
    permissions.go           # uses GetAccountAuthorizationDetails
    pmapper.go               # runs principal-mapper as subprocess
    principals.go
    ram.go                   # Resource Access Manager (cross-account share)
    resource-trusts.go       # S3/SNS/SQS/Lambda resource policies
    role-trusts.go           # IAM role trust policies
    route53.go
    secrets.go
    shared.go                # OutputClient, table/CSV/JSON writers
    sns.go sqs.go
    tags.go
    workloads.go             # combined containers/serverless inventory
  azure/                     # whoami, inventory, rbac, storage, vms
  gcp/                       # 60+ subcommands
  globals/                   # shared constants
  internal/                  # OutputClient, color, spinner (charmbracelet/lipgloss)
```

**Command flow:** cobra parses → `cli/aws.go` resolves subcommand → instantiates the corresponding `<Cmd>Module` struct → `Module.PrintIncidents(...)` runs:
1. Initialize SDK clients (`client-initializers.go`).
2. Concurrent enumeration: goroutines per region/resource, bounded by a semaphore channel.
3. Receiver goroutine collects rows.
4. `OutputClient.WriteOutput(...)` produces terminal table + loot files.

**Concurrency pattern (idiomatic Go, must mirror in Rust):**
```go
sem := make(chan struct{}, 10)              // max 10 concurrent
var wg sync.WaitGroup
out := make(chan BucketRow, 100)
for _, b := range buckets {
    wg.Add(1)
    sem <- struct{}{}
    go func(b string) {
        defer wg.Done()
        defer func(){ <-sem }()
        row := analyzeBucket(b)
        out <- row
    }(b)
}
go func() { wg.Wait(); close(out) }()
for row := range out { rows = append(rows, row) }
```
Rust equivalent: `tokio::task::JoinSet` + `Semaphore` from `tokio::sync`.

## LOOT file format

Naming convention (verified from buckets.go):
```
~/.cloudfox/cloudfox-output/aws/{profile}-{account-id}/
  loot/
    bucket-commands.txt          # AWS CLI commands per resource for manual followup
    bucket-policies/
      {bucket-name}.json         # raw JSON resource policies
    eks-tokens-{cluster}.txt
    env-vars-{service}.csv
    iam-simulator-pmapper-commands.txt
    lambda-iam-trust-policies/{function}.json
    role-trusts-PrincipalsThatCanAssumeRoles.txt
    secrets-{secret-id}.txt
  table/
    {command}.txt                # the same table rendered to file
    {command}.csv
    {command}.json
  *.md                            # markdown report variants
```

The **loot** model is "what you grep next". Every file is a primitive (CSV, JSON, or shell-paste-ready txt). Adopting this verbatim in Rust is trivial — `serde_json::to_writer_pretty` + `std::fs::write`.

## Subcommand catalog (full)

**AWS (~34 subcommands):** access-keys, all-checks, api-gw, buckets, cape, cloudformation, codebuild, databases, ds, ecr, ecs-tasks, eks, elastic-network-interfaces, endpoints, env-vars, filesystems, iam-simulator, instances, inventory, lambda, network-ports, orgs, outbound-assumed-roles, permissions, pmapper, principals, ram, resource-trusts, role-trusts, route53, secrets, sns, sqs, tags, workloads.

**Azure (~5 subcommands):** whoami, inventory, rbac, storage, vms.

**GCP (~60 subcommands):** whoami, iam, permissions, serviceaccounts, service-agents, keys, resource-iam, domain-wide-delegation, privesc, hidden-admins, identity-federation, instances, gke, cloudrun, functions, app-engine, composer, dataproc, dataflow, notebooks, workload-identity, inventory, storage, storage-enum, bigquery, cloudsql, spanner, bigtable, filestore, memorystore, vpc-networks, firewall, loadbalancers, dns, endpoints, private-service-connect, network-topology, vpc-sc, access-levels, cloud-armor, iap, beyondcorp, kms, secrets, cert-manager, org-policies, artifact-registry, cloudbuild, source-repos, scheduler, pubsub, logging, organizations, asset-inventory, backup-inventory, lateral-movement, data-exfiltration, public-access, cross-project, foxmapper, logging-enum, bigquery-enum, bigtable-enum, spanner-enum.

The killer commands:
- **`cape`** — Cross-Account Privilege Escalation. Requires `pmapper` data already collected. Combines pmapper graphs across accounts to find chains.
- **`role-trusts`** / **`resource-trusts`** — parse IAM trust policies & resource policies (S3, SNS, SQS, Lambda) and surface trusted principals (Account ID, ARN, federation, wildcards).
- **`iam-simulator`** — invokes `iam:SimulatePrincipalPolicy` for a curated list of high-impact actions (`sts:AssumeRole`, `iam:PassRole`, `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:SendCommand`, etc.) against every principal.
- **`pmapper`** — orchestrates running Bishop Fox's Python `principalmapper` and ingesting its SQLite output.
- **`network-ports`** — translates security group rules into a {host:port:source-cidr} matrix.
- **`env-vars`** — extracts environment variables from Lambda, ECS task defs, CodeBuild, App Runner, etc. (gold mine for accidentally-stored secrets).
- **`secrets`** — lists Secrets Manager + SSM Parameter Store entries and *does not* fetch values by default (only metadata).

## Engineering hard parts

**Trust graph computation (`graph.go`):** Build a directed graph: nodes = `Principal` (User/Role/Account/Federated); edges = `CanAssume` (from role-trust policy) and `IsTrustedBy` (from resource policy). Use `petgraph` in Rust. Persist to GraphML or DOT.

**IAM simulator:** the `iam:SimulatePrincipalPolicy` API caps at 50 actions / 100 resources per call. Batch carefully. Default action list (~15 actions) from `iam-simulator.go`:
```
sts:AssumeRole, iam:PassRole,
secretsmanager:GetSecretValue,
ssm:GetParameter, ssm:SendCommand,
s3:ListBucket, s3:GetObject,
ecr:BatchGetImage,
lambda:ListFunctions,
eks:UpdateClusterConfig,
sns:Subscribe, sqs:SendMessage,
iam:PutUserPolicy, iam:AttachRolePolicy
```
Plus admin-detection set: `iam:PutUserPolicy`, `iam:AttachUserPolicy`, `iam:CreateAccessKey`, etc.

**pmapper integration:** subprocess `pmapper` binary, ingest the SQLite DB it writes to `~/.principalmapper/`. In a Rust clone, *port* pmapper rather than shell out — it's another ~3000 LoC graph problem. petgraph + the 21 privesc paths + cross-account `sts:AssumeRole` edges = pmapper-equivalent.

**Output complexity:** every subcommand emits 3+ files (table, JSON, loot). Build a single `OutputWriter` abstraction:
```rust
struct OutputWriter { base: PathBuf }
impl OutputWriter {
    fn table<T: Row>(&self, name: &str, rows: &[T]);   // comfy-table + .txt
    fn csv<T: Serialize>(&self, name: &str, rows: &[T]);
    fn json<T: Serialize>(&self, name: &str, data: &T);
    fn loot_file(&self, dir: &str, name: &str, body: impl AsRef<[u8]>);
    fn loot_commands(&self, body: &str);  // copy-paste shell commands
}
```

## Rust library mapping

```toml
[dependencies]
aws-config = "1.8"
# all relevant aws-sdk-* crates (same as Prowler)

# Azure
azure_identity = "0.21"
azure_mgmt_authorization = "0.21"  # RBAC
azure_mgmt_compute = "0.21"
azure_mgmt_storage = "0.21"

# GCP
google-cloud-iam = "0.5"
google-cloud-resourcemanager = "0.5"
google-cloud-storage = "0.20"
google-cloud-compute = "0.5"

# CLI + output
clap = { version = "4.5", features = ["derive"] }
comfy-table = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1.3"
colored = "2"
indicatif = "0.17"

# Graph (for cape / pmapper)
petgraph = "0.6"

# IAM policy parsing/evaluation
aws-iam = "0.4"   # or build it

# Async
tokio = { version = "1.40", features = ["full"] }
```

## SDK-specific gotchas

- **`GetAccountAuthorizationDetails`** is the most efficient IAM enum call — single API for users/groups/roles/policies with attached + inline. Use it before `ListUsers/ListRoles/...` separately. Returns paginated `Marker` token.
- **`SimulatePrincipalPolicy`** — caller needs `iam:SimulatePrincipalPolicy`; if scoped down, fall back to manual policy parsing.
- **Cross-account trust edges:** `AssumeRolePolicyDocument` has `Principal.AWS` which can be: account ID (`arn:aws:iam::123:root`), explicit user/role ARN, federation provider (SAML, OIDC), wildcard (`*`). Need policy DSL parser to handle `Condition` blocks (e.g., `aws:PrincipalOrgID`).
- **Resource policies** vary wildly: S3 bucket policies (`s3:GetBucketPolicy`), SNS topic policies (`sns:GetTopicAttributes`), SQS queue policies (`sqs:GetQueueAttributes`), Lambda resource policies (`lambda:GetPolicy`), Secrets Manager (`secretsmanager:GetResourcePolicy`).
- **GCP IAM:** every resource has its own IAM policy. `getIamPolicy` per resource — N+1 problem. Use `cloudasset.googleapis.com/v1/searchAllIamPolicies` to bulk-fetch.

## 2024-2026 state

- v2.0 (2025) added GCP module (60+ subcommands) — major feature parity bump.
- `cape` command (cross-account privesc) added 2024.
- TUI variant for `cape` (`cape-tui.go`) uses `bubbletea` — for Rust clone, `ratatui` is the equivalent.
- Azure module remains thin (~5 subcommands) — opportunity for the clone to do better.

### Release timeline (verified from GitHub releases page)

| Version | Date | Highlights |
|---------|------|-----------|
| v1.14.0 | 2023 | `cape` (Cross-Account Privesc Enum) introduced |
| v1.15.0 | Oct 2023 | Admin/PMapper logic added to `principals`; `--admin-check-only` flag added to `iam-simulator` |
| v1.17.0 | Dec 2023 | Breaking change for AWS JSON format updates; Route53 Alias record support; KMS integrated into `resource-trusts`; enhanced ECS task enumeration. **Minimum supported version** — all earlier versions stopped working after AWS service-mapping format change. |
| v2.0.0 | Mar 2024 | Major release: GCP module (60+ subcommands), hierarchical output formatting (Org → Folder → Project → Resource), integrated attack-path analysis, new data-exfiltration detection. |
| v2.0.1 | Mar 2024 | OpenTelemetry SDK CVE-2026-24051 patch |
| v2.0.2 | Apr 2024 | Fix `secrets` command (stale service slug names skipping all regions) |
| v2.0.3 | Apr 2024 | Go 1.25.9 upgrade; AWS SDK GHSA-xmrv-pmrh-hhx2 patch |
| v2.0.4 | Apr 2024 | Fix `--pmapper-data-basepath` ignored in `all-checks` EC2 user-data module; race-condition fix in `instances` |
| v2.0.5 | May 2026 | Current latest stable |

### Newly-confirmed AWS commands / flags (added since v1.14.0 and must port)

- **`cape`** (v1.14.0+): now supports `--admin-only` flag (faster cross-account analysis, only admins) and a `tui` subcommand for the terminal UI.
- **`pmapper`**: `--pmapper-data-basepath` flag to point at non-default pmapper SQLite location.
- **`iam-simulator`**: `--admin-check-only` flag (v1.15.0+) — restricts simulation to admin-grant action set only, much faster.
- **`principals`**: now resolves admin status via PMapper logic if pmapper data is available.
- **`resource-trusts`**: KMS policies added (v1.17.0+) — KMS key resource policies are now in scope.
- **`route53`**: Alias records now resolved (v1.17.0+).
- **`ecs-tasks`**: enhanced enumeration — task-definition env-vars surfaced separately.
- Global flags worth pinning in parity tests: `-p/--profile`, `-l <profile-list-file>` (multi-account scan), `--filter`, `--userdata` (extract EC2 user data), `--max-resources-per-region`, `--skip-admin-check`.

### Confirmed AWS output formats (parity required)

- `table` (terminal, default)
- `csv` (machine-readable, per-row)
- `json` (full record, machine-readable)
- `txt` (rendered table mirror)
- `loot/` files — shell-paste-ready commands (nmap, docker, AWS CLI)
- **SARIF** (Static Analysis Results Interchange Format) — security-findings-standard output, useful for piping into code-scanning dashboards
- **Markdown** (`.md`) — report variants

### GCP module — full catalog (v2.0+, 60-64 subcommands)

Organized into 5 logical categories (must mirror in `lancer-cloudfox gcp ...`):

1. **Identity & Access Management** — `whoami`, `iam`, `permissions`, `principals`, `serviceaccounts`, `service-agents`, `keys`, `resource-iam`, `domain-wide-delegation`, `workload-identity`, `identity-federation`, `hidden-admins`.
2. **Storage & Secrets** — `buckets`, `storage`, `storage-enum`, `secrets`, `kms`, `bigquery`, `bigquery-enum`, `cloudsql`, `spanner`, `spanner-enum`, `bigtable`, `bigtable-enum`, `filestore`, `memorystore`, `artifact-registry`, `source-repos`.
3. **Compute & Containers** — `instances`, `gke`, `cloudrun`, `functions`, `app-engine`, `composer`, `dataproc`, `dataflow`, `notebooks` (Vertex AI Notebooks exposure detection), `cloudbuild`, `scheduler`.
4. **Network** — `vpc-networks` (incl. Shared VPC host/service-project analysis), `firewall`, `loadbalancers`, `dns`, `endpoints`, `private-service-connect`, `network-topology`, `vpc-sc`, `access-levels`, `cloud-armor`, `iap`, `beyondcorp`.
5. **Attack-path analysis** — `privesc` (60+ techniques, FoxMapper-backed), `lateral-movement`, `data-exfiltration`, `public-access` (allUsers/allAuthenticatedUsers across 16 services), `cross-project` (cross-project IAM + lateral movement), `foxmapper` (graph builder/visualizer), `logging-enum`, `pubsub`, `logging`, `organizations`, `asset-inventory`, `backup-inventory`, `org-policies`, `cert-manager`.

### FoxMapper (NEW, replaces pmapper for GCP and unifies AWS+GCP graphs)

- FoxMapper is Bishop Fox's **modern rewrite and extension of NCC Group's PMapper** (Python `principalmapper`).
- Builds IAM permission graphs identifying: **service-account impersonation chains**, **multi-step privilege escalation paths**, and **permission-chaining vulnerability patterns**.
- Surfaces **60+ known privilege-escalation techniques** for GCP (service-account impersonation, key creation, IAM policy modification, resource-deployment abuse) with ready-to-use exploitation playbooks.
- When FoxMapper data is available, GCP `privesc`, `lateral-movement`, and `data-exfiltration` modules leverage its graph for attack-path enumeration.
- **Rust port implication:** the existing `## Engineering hard parts` pmapper section now also needs a `lancer-cloudfox-foxmapper` port — same `petgraph` core, but extended with GCP IAM semantics (org/folder/project inheritance) on top of AWS.

### Hierarchical output formatting (NEW in v2.0)

- GCP output respects GCP's organizational hierarchy: **Organization → Folders → Projects → Resources**.
- Loot-file layout under `~/.cloudfox/cloudfox-output/gcp/{org-id}/{folder-id}/{project-id}/...`
- AWS retained the flat `{profile}-{account-id}/` layout; GCP introduced nested directories.
- Rust `OutputWriter` abstraction (see `## Engineering hard parts`) must accept a hierarchy path, not just `{profile}-{account-id}`.

### Wiki / docs state (verified 2026-05)

- Wiki has 4 pages: Home, AWS Commands, Azure Commands, GCP Commands (no separate FoxMapper / CAPE / output-format / config pages yet).
- Last home-page edit: 2026-02-26 by jbarciabf.

### Gaps to ADD to `lancer-cloudfox` parity catalog (delta vs the original plan above)

1. **AWS `cape tui` subcommand** — explicitly a child command of `cape` (not just a flag).
2. **AWS `cape --admin-only`** flag.
3. **AWS `iam-simulator --admin-check-only`** flag.
4. **AWS `pmapper --pmapper-data-basepath`** flag (must thread through `all-checks` to EC2 user-data and every dependent module).
5. **AWS `resource-trusts` KMS coverage** — KMS key resource policies must be parsed alongside S3/SNS/SQS/Lambda/Secrets Manager.
6. **AWS `route53` Alias record resolution**.
7. **AWS multi-profile mode** — `-l <profile-list-file>` flag for scanning many AWS accounts in one invocation.
8. **AWS `--userdata`** flag on `instances` (extract EC2 user data into loot).
9. **AWS `--max-resources-per-region`** flag (throttling for huge accounts).
10. **AWS `--skip-admin-check`** flag (performance).
11. **SARIF output format** for AWS, Azure, GCP — currently the plan only lists txt/CSV/JSON. SARIF must be added to the `OutputWriter` abstraction as `fn sarif<T: Serialize>(&self, name: &str, findings: &[T])`.
12. **Markdown report output** — `.md` variants generated per command.
13. **GCP `notebooks` (Vertex AI Notebooks exposure detection)** — was implied under "notebooks" but the exposure-specific check is its own deliverable.
14. **GCP `cross-project` module** — explicit cross-project IAM + lateral-movement analysis (distinct from `lateral-movement`).
15. **GCP `public-access` 16-service coverage** — must enumerate `allUsers`/`allAuthenticatedUsers` across at least Storage, BigQuery, Cloud Run, Cloud Functions, App Engine, KMS, Secret Manager, Artifact Registry, Source Repos, Pub/Sub, Cloud SQL (auth networks), Compute (firewall 0.0.0.0/0), Cloud Build, Scheduler, Logging, IAP-backed.
16. **GCP hierarchical output** — Organization → Folders → Projects → Resources directory layout (new `OutputWriter` contract).
17. **FoxMapper port** — a dedicated `lancer-cloudfox-foxmapper` binary (Bishop Fox is shipping FoxMapper as a separate tool); must replace the "shell out to pmapper" approach for both AWS and GCP. Unified graph schema for cross-cloud attack paths.
18. **GCP 60+ privesc techniques playbook bundle** — each technique = an `.md` playbook in loot, generated when the graph hits that pattern.
19. **GCP `domain-wide-delegation`** — detects Google Workspace impersonation risk (DWD enabled on service accounts).
20. **GCP `workload-identity` misconfig detection** — GKE Workload Identity binding audit.
21. **GCP `iam-inheritance` resolver** — propagate Org/Folder/Project IAM bindings down to resources before answering "who can do X on resource Y?".
22. **`--cli` fall-through** — the GUI is the default; CLI surface must accept every upstream flag verbatim behind `--cli`.

### Implementation-phase impact

- Original phase 11 ("GCP module: top-15 most-used subcommands") is **insufficient** for full parity — must expand to the full 60-64 GCP subcommand set. Add phases 13-14:
  - Phase 13: GCP storage/network/compute (remaining ~30 subcommands beyond top-15)
  - Phase 14: GCP attack-path analysis (`privesc`, `lateral-movement`, `data-exfiltration`, `public-access`, `cross-project`, `foxmapper`) + FoxMapper graph port
- Add phase 15: SARIF + Markdown report writers across AWS/Azure/GCP.

### Dated research note

- **2026-05-30** — Deep-research pass against upstream `github.com/BishopFox/cloudfox` (latest stable **v2.0.5**, May 2026), GCP launch blog (Feb 2026), and wiki (last touched 2026-02-26). Confirmed: 34 AWS subcommands, 4-5 Azure, 60-64 GCP. Added 22 explicit parity gaps above (cape-tui, cape --admin-only, iam-simulator --admin-check-only, pmapper --pmapper-data-basepath, resource-trusts KMS, route53 Alias, -l multi-profile, --userdata, --max-resources-per-region, --skip-admin-check, SARIF, Markdown, Vertex AI Notebooks exposure, cross-project, 16-service public-access matrix, hierarchical output layout, FoxMapper port as own binary, 60+ GCP privesc playbooks, domain-wide-delegation, workload-identity misconfig, IAM-inheritance resolver, --cli fall-through). FoxMapper is being released as a separate Bishop Fox tool that is a rewrite of NCC Group's PMapper — `lancer-cloudfox` must port it natively (no shell-out) and unify AWS + GCP graphs under a single petgraph schema.

## Validation environment

- **CloudGoat** (multi-account scenarios) — best for `cape` and `role-trusts` testing.
- **AWS Organizations sandbox** with two child accounts and bidirectional `sts:AssumeRole` to validate cross-account graph edges.
- **LocalStack** for basic enumeration validation (S3, IAM, Lambda).
- **GCP free tier** project + Terraform `goat` lab.

## Real-world authorized usage

Bug bounty workflow:
1. Receive scoped IAM user from program with `ReadOnlyAccess` + `SecurityAudit`.
2. Run `lancer-cloudfox aws inventory --regions us-east-1,eu-west-1`.
3. Run `lancer-cloudfox aws all-checks` (runs every read-only subcommand).
4. Review `loot/` for env vars / secrets / public buckets.
5. Submit findings citing specific resource ARNs from loot files.

CloudFox is **fully read-only** for AWS — every API call is `List*` / `Describe*` / `Get*` / `Simulate*`. No write operations. Safer to ship than Pacu. CloudTrail footprint is heavy but expected; mention in report.

## AI augmentation ideas

- **Attack chain ranker:** given the cross-account graph from `cape`, LLM ranks the top-10 most impactful chains (e.g., "chain X → admin in prod payments account").
- **Loot file summarizer:** `lancer-cloudfox aws ai-summarize` digests all loot into a 1-page exec summary.
- **Env-var secret classifier:** LLM scans `env-vars.csv` rows for `STRIPE_KEY`, `DB_PASS`, etc., scores severity.
- **Resource policy explainer:** for each weird trust policy, generate plain-English "this allows account 999... to assume this role with condition Y."
- **Asset-to-bounty matcher:** correlate discovered resources with the program's scope JSON.

## Implementation phases (12 weeks)

| Week | Deliverable |
|------|-------------|
| 1 | clap skeleton, OutputWriter abstraction, AWS client factory, `whoami` + `inventory` subcommands |
| 2 | `principals` + `permissions` (uses `GetAccountAuthorizationDetails`) |
| 3 | `role-trusts` + `resource-trusts` (IAM policy DSL parser) |
| 4 | `iam-simulator` with `SimulatePrincipalPolicy` batching |
| 5 | `buckets`, `secrets`, `env-vars` (lambda + ecs + codebuild) |
| 6 | `instances`, `network-ports`, `lambda`, `databases` |
| 7 | `route53`, `cloudformation`, `eks`, `ecr` |
| 8 | `graph.go` Rust port with petgraph (DOT/GraphML output) |
| 9 | `cape` cross-account privesc enumeration (port pmapper logic) |
| 10 | Azure module: `whoami`, `inventory`, `rbac`, `storage`, `vms` |
| 11 | GCP module: top-15 most-used subcommands (`iam`, `serviceaccounts`, `privesc`, `storage`, `gke`, ...) |
| 12 | TUI for `cape` (ratatui), `all-checks` aggregator, benchmark vs upstream |

---

## GUI (Lancer-standard pattern)

`lancer-cloudfox` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-cloudfox-cli` companion binary), but the **plain `lancer-cloudfox` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-cloudfox/`, `%APPDATA%\lancer-cloudfox\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-cloudfox-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-cloudfox.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-cloudfox.exe` (double-click opens the GUI window).
- Linux: `build/lancer-cloudfox` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-cloudfox` (bundled into `lancer-cloudfox.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-cloudfox/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-cloudfox.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-cloudfox-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-cloudfox
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-cloudfox.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-cloudfox-windows-x86_64\bin\lancer-cloudfox.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-cloudfox`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
