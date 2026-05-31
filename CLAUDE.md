# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-cloudfox` is a Rust clone of the `cloudfox` cloud-enumeration tool, built as part of the Lancer ecosystem — a complete 2026 AI-era bug bounty toolkit. It enumerates AWS, Azure, and GCP cloud environments to surface misconfigurations, exposed secrets, IAM trust relationships, and attack paths useful during bug bounty and penetration testing engagements. The project is currently in active scaffold development, with full implementation tracked in the local `plan.md`.

## Architecture

- `src/main.rs` — binary entry point; sets up async runtime and dispatches CLI subcommands
- `src/cli/` — CLI surface definition via `clap`; subcommands for `aws`, `azure`, and `gcp` provider modules
- `src/aws/` — AWS enumeration modules: `whoami`, `instances`, `buckets`, `secrets`, `iam_simulator`, `permissions`, `principals`, `role_trusts`, `resource_trusts`, `cape`, `lambda_fn`, `databases`, `ecr`, `eks`, `env_vars`, `network_ports`, `route53`, `cloudformation`, `inventory`, `all_checks`, `graph`, and `client`
- `src/azure/` — Azure enumeration modules: `whoami`, `inventory`, `storage`, `vms`, `rbac`, `client`
- `src/gcp/` — GCP enumeration modules: `whoami`, `inventory`, `instances`, `storage`, `secrets`, `iam`, `serviceaccounts`, `functions`, `cloudrun`, `cloudsql`, `bigquery`, `gke`, `kms`, `privesc`, `client`
- `src/tui/` — Terminal UI layer (ratatui/crossterm); `cape.rs` for trust-graph visualization
- `src/output.rs` — Shared output formatting: tables (`comfy-table`), JSON (`serde_json`), CSV (`csv`), and colored terminal output

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- AWS SDK dependencies use `default-features = false` and supply `rustls-ring` via `aws-smithy-http-client` to avoid C toolchain requirements.
- Library code is organized per cloud provider under `src/aws/`, `src/azure/`, `src/gcp/`; binary entry point in `src/main.rs`.
- Async runtime is `tokio` with `features = ["full"]`; all cloud SDK calls are async.
- Graph/trust-mapping uses `petgraph`; TUI visualization uses `ratatui` + `crossterm`.
- Logging uses `tracing` + `tracing-subscriber` with env-filter support (`RUST_LOG`).

## Build / test / run

```
build.bat                   # Windows → build\lancer-cloudfox.exe
build-windows.bat           # Windows dist build → dist\lancer-cloudfox-windows-x86_64\bin\lancer-cloudfox.exe
./build-linux.sh            # Linux/macOS → build/lancer-cloudfox
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

**Requirements:** Rust/Cargo (rustup.rs); on Windows, Visual C++ Build Tools 2019/2022.

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
