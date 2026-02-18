use clap::{ArgAction, Args, Parser, Subcommand};
use std::path::PathBuf;

pub const DEFAULT_BASE_REF: &str = "main";
pub const DEFAULT_IMAGE: &str = "ubuntu:24.04";
pub const DEFAULT_CPUS: &str = "2";
pub const DEFAULT_MEMORY: &str = "4g";
pub const DEFAULT_PIDS_LIMIT: i64 = 256;
pub const DEFAULT_JOBS: usize = 1;

#[derive(Debug, Parser)]
#[command(name = "normies")]
#[command(about = "Git-centric multi-agent orchestrator with Docker-isolated execution.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Run(RunArgs),
    Retry(RetryArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Review(ReviewArgs),
    Integrate(IntegrateArgs),
    Cleanup(CleanupArgs),
    Doctor(DoctorArgs),
    Init(InitArgs),
    MakeSpec(MakeSpecArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long)]
    pub spec: PathBuf,
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, default_value_t = DEFAULT_JOBS)]
    pub jobs: usize,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RetryArgs {
    #[arg(long = "run-id")]
    pub run_id: String,
    #[arg(long, action = ArgAction::SetTrue)]
    pub failed: bool,
    #[arg(long, default_value_t = DEFAULT_JOBS)]
    pub jobs: usize,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub latest: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub latest: bool,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long = "list-agents", action = ArgAction::SetTrue)]
    pub list_agents: bool,
    #[arg(long)]
    pub tail: Option<usize>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub follow: bool,
}

#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub latest: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct IntegrateArgs {
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub latest: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CleanupArgs {
    #[arg(long = "run-id")]
    pub run_id: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub latest: bool,
    #[arg(long = "remove-run-dir", action = ArgAction::SetTrue)]
    pub remove_run_dir: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long, default_value = "normies.spec.json")]
    pub output: PathBuf,
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long, default_value = "baseline")]
    pub template: String,
    #[arg(long, action = ArgAction::SetTrue)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct MakeSpecArgs {
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub repo: Option<String>,
    #[arg(long = "base-ref", default_value = DEFAULT_BASE_REF)]
    pub base_ref: String,
    #[arg(long, default_value = DEFAULT_IMAGE)]
    pub image: String,
    #[arg(long = "agent")]
    pub agents: Vec<String>,
    #[arg(long = "network-agent")]
    pub network_agents: Vec<String>,
    #[arg(long = "check")]
    pub checks: Vec<String>,
    #[arg(long, default_value = DEFAULT_CPUS)]
    pub cpus: String,
    #[arg(long, default_value = DEFAULT_MEMORY)]
    pub memory: String,
    #[arg(long = "pids-limit", default_value_t = DEFAULT_PIDS_LIMIT)]
    pub pids_limit: i64,
    #[arg(long = "auto-commit", action = ArgAction::SetTrue)]
    pub auto_commit: bool,
    #[arg(long = "no-auto-commit", action = ArgAction::SetTrue)]
    pub no_auto_commit: bool,
}
