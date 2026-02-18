use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

pub const CURRENT_SPEC_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub schema_version: Option<u32>,
    pub repo: Option<String>,
    pub base_ref: Option<String>,
    pub image: Option<String>,
    pub defaults: Option<SpecDefaults>,
    pub review: Option<ReviewConfig>,
    pub a2a_gateway: Option<A2aGatewayConfig>,
    #[serde(default)]
    pub agents: Vec<AgentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SpecDefaults {
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub pids_limit: Option<i64>,
    pub needs_network: Option<bool>,
    pub auto_commit: Option<bool>,
    pub read_only_rootfs: Option<bool>,
    pub commit_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReviewConfig {
    #[serde(default)]
    pub required_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct A2aGatewayConfig {
    pub enabled: bool,
    pub transport: String,
    pub auth: String,
    pub bind_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub stream_idle_timeout_ms: u64,
    pub max_payload_bytes: usize,
}

impl Default for A2aGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            transport: "uds".to_string(),
            auth: "bearer".to_string(),
            bind_timeout_ms: 2_000,
            request_timeout_ms: 30_000,
            stream_idle_timeout_ms: 120_000,
            max_payload_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentSkillSpec {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentA2aConfig {
    pub serve: bool,
    pub description: Option<String>,
    #[serde(default)]
    pub skills: Vec<AgentSkillSpec>,
    pub streaming: Option<bool>,
}

impl Default for AgentA2aConfig {
    fn default() -> Self {
        Self {
            serve: false,
            description: None,
            skills: vec![],
            streaming: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    pub cmd: String,
    pub base_ref: Option<String>,
    pub image: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub pids_limit: Option<i64>,
    pub needs_network: Option<bool>,
    pub read_only_rootfs: Option<bool>,
    pub auto_commit: Option<bool>,
    pub commit_prefix: Option<String>,
    pub commit_message: Option<String>,
    #[serde(default)]
    pub required_checks: Vec<String>,
    pub a2a: Option<AgentA2aConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub name: String,
    pub branch: String,
    pub base_ref: String,
    pub before_head: String,
    pub after_head: String,
    pub committed: bool,
    pub auto_committed: bool,
    pub dirty_uncommitted: bool,
    pub exit_code: i32,
    pub status: String,
    pub summary: String,
    pub worktree: String,
    pub out_dir: String,
    pub log_path: String,
    pub image: String,
    pub cmd: String,
    pub needs_network: bool,
    pub read_only_rootfs: bool,
    pub required_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub repo_input: String,
    pub repo_resolved: String,
    pub repo_key: String,
    pub hub_path: String,
    pub base_ref: String,
    pub integration_branch: String,
    pub spec_path: String,
    pub agents: Vec<AgentState>,
    pub state: String,
    pub review: Option<Value>,
    pub integration: Option<Value>,
    pub gateway: Option<GatewayTelemetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayTelemetry {
    pub enabled: bool,
    pub transport: String,
    pub socket_path: String,
    pub started_at: String,
    pub stopped_at: String,
    pub requests_total: u64,
    pub auth_failures: u64,
    pub proxy_errors: u64,
    pub stream_sessions_peak: u64,
}

#[derive(Debug)]
pub struct CmdOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub struct CommitInfo {
    pub committed: bool,
    pub auto_committed: bool,
    pub dirty_uncommitted: bool,
    pub after_head: String,
}

#[derive(Debug, Clone)]
pub struct PreparedAgent {
    pub name: String,
    pub branch: String,
    pub base_ref: String,
    pub before_head: String,
    pub worktree: PathBuf,
    pub out_dir: PathBuf,
    pub log_path: PathBuf,
    pub image: String,
    pub cmd: String,
    pub needs_network: bool,
    pub read_only_rootfs: bool,
    pub required_checks: Vec<String>,
    pub auto_commit: bool,
    pub commit_prefix: String,
    pub commit_message: Option<String>,
    pub cpus: String,
    pub memory: String,
    pub pids_limit: i64,
    pub container_name: String,
    pub env_map: HashMap<String, String>,
    pub gateway_dir: Option<PathBuf>,
}
