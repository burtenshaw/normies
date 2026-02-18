use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use clap::{ArgAction, Args, Parser, Subcommand};
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_BASE_REF: &str = "main";
const DEFAULT_IMAGE: &str = "ubuntu:24.04";
const DEFAULT_CPUS: &str = "2";
const DEFAULT_MEMORY: &str = "4g";
const DEFAULT_PIDS_LIMIT: i64 = 256;
const ORCH_DIR_ENV: &str = "NORMIES_ORCH_DIR";
const FAKE_DOCKER_ENV: &str = "NORMIES_TEST_FAKE_DOCKER";

#[derive(Debug, Parser)]
#[command(name = "normies")]
#[command(about = "Git-centric multi-agent orchestrator with Docker-isolated execution.")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run(RunArgs),
    Status(StatusArgs),
    Logs(LogsArgs),
    Review(ReviewArgs),
    Integrate(IntegrateArgs),
    Publish(PublishArgs),
    Cleanup(CleanupArgs),
    MakeSpec(MakeSpecArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long)]
    repo: Option<String>,
    #[arg(long)]
    spec: PathBuf,
    #[arg(long = "run-id")]
    run_id: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long = "run-id")]
    run_id: Option<String>,
}

#[derive(Debug, Args)]
struct LogsArgs {
    #[arg(long = "run-id")]
    run_id: String,
    #[arg(long)]
    agent: String,
}

#[derive(Debug, Args)]
struct ReviewArgs {
    #[arg(long = "run-id")]
    run_id: String,
}

#[derive(Debug, Args)]
struct IntegrateArgs {
    #[arg(long = "run-id")]
    run_id: String,
}

#[derive(Debug, Args)]
struct PublishArgs {
    #[arg(long = "run-id")]
    run_id: String,
    #[arg(long)]
    remote: Option<String>,
    #[arg(long = "final-branch")]
    final_branch: Option<String>,
    #[arg(long = "final-pr", action = ArgAction::SetTrue)]
    final_pr: bool,
    #[arg(long = "base-branch")]
    base_branch: Option<String>,
    #[arg(long)]
    title: Option<String>,
}

#[derive(Debug, Args)]
struct CleanupArgs {
    #[arg(long = "run-id")]
    run_id: String,
    #[arg(long = "remove-run-dir", action = ArgAction::SetTrue)]
    remove_run_dir: bool,
}

#[derive(Debug, Args)]
struct MakeSpecArgs {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    repo: Option<String>,
    #[arg(long = "base-ref", default_value = DEFAULT_BASE_REF)]
    base_ref: String,
    #[arg(long, default_value = DEFAULT_IMAGE)]
    image: String,
    #[arg(long = "agent")]
    agents: Vec<String>,
    #[arg(long = "network-agent")]
    network_agents: Vec<String>,
    #[arg(long = "check")]
    checks: Vec<String>,
    #[arg(long, default_value = DEFAULT_CPUS)]
    cpus: String,
    #[arg(long, default_value = DEFAULT_MEMORY)]
    memory: String,
    #[arg(long = "pids-limit", default_value_t = DEFAULT_PIDS_LIMIT)]
    pids_limit: i64,
    #[arg(long = "auto-commit", default_value_t = true)]
    auto_commit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Spec {
    repo: Option<String>,
    base_ref: Option<String>,
    image: Option<String>,
    defaults: Option<SpecDefaults>,
    review: Option<ReviewConfig>,
    #[serde(default)]
    agents: Vec<AgentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SpecDefaults {
    cpus: Option<String>,
    memory: Option<String>,
    pids_limit: Option<i64>,
    needs_network: Option<bool>,
    auto_commit: Option<bool>,
    read_only_rootfs: Option<bool>,
    commit_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReviewConfig {
    #[serde(default)]
    required_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentSpec {
    name: String,
    cmd: String,
    base_ref: Option<String>,
    image: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    cpus: Option<String>,
    memory: Option<String>,
    pids_limit: Option<i64>,
    needs_network: Option<bool>,
    read_only_rootfs: Option<bool>,
    auto_commit: Option<bool>,
    commit_prefix: Option<String>,
    commit_message: Option<String>,
    #[serde(default)]
    required_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentState {
    name: String,
    branch: String,
    base_ref: String,
    before_head: String,
    after_head: String,
    committed: bool,
    auto_committed: bool,
    dirty_uncommitted: bool,
    exit_code: i32,
    status: String,
    summary: String,
    worktree: String,
    out_dir: String,
    log_path: String,
    image: String,
    cmd: String,
    needs_network: bool,
    read_only_rootfs: bool,
    required_checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunManifest {
    run_id: String,
    created_at: String,
    updated_at: String,
    repo_input: String,
    repo_resolved: String,
    repo_key: String,
    hub_path: String,
    remote_name: String,
    base_ref: String,
    integration_branch: String,
    final_branch: String,
    spec_path: String,
    agents: Vec<AgentState>,
    state: String,
    review: Option<Value>,
    integration: Option<Value>,
    published: Option<Value>,
}

#[derive(Debug)]
struct CmdOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
pub struct CommitInfo {
    pub committed: bool,
    pub auto_committed: bool,
    pub dirty_uncommitted: bool,
    pub after_head: String,
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Run(args) => cmd_run(&args),
        Commands::Status(args) => cmd_status(&args),
        Commands::Logs(args) => cmd_logs(&args),
        Commands::Review(args) => cmd_review(&args),
        Commands::Integrate(args) => cmd_integrate(&args),
        Commands::Publish(args) => cmd_publish(&args),
        Commands::Cleanup(args) => cmd_cleanup(&args),
        Commands::MakeSpec(args) => cmd_make_spec(&args),
    };
    match result {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("error: {err}");
            2
        }
    }
}

fn cmd_run(args: &RunArgs) -> Result<()> {
    check_tool_exists("git")?;
    check_tool_exists("docker")?;
    ensure_docker_daemon()?;
    ensure_orch_dirs()?;

    let spec_path = args.spec.canonicalize().context("spec file not found")?;
    let spec = load_spec(&spec_path)?;
    validate_spec(&spec)?;

    let repo_input = args
        .repo
        .clone()
        .or(spec.repo.clone())
        .ok_or_else(|| anyhow!("repo must be provided via --repo or spec.repo"))?;

    let normalized_repo = normalize_repo_input(&repo_input)?;
    let repo_key = sanitize_repo_key(&normalized_repo);
    let hub_path = ensure_hub(&normalized_repo, &repo_key)?;

    let run_id = args.run_id.clone().unwrap_or_else(create_run_id);
    let run_dir = runs_dir().join(&run_id);
    if run_dir.exists() {
        bail!("run_id already exists: {run_id}");
    }
    mkdirp(&run_dir.join("agents"))?;

    let base_ref = spec
        .base_ref
        .clone()
        .unwrap_or_else(|| DEFAULT_BASE_REF.to_string());
    resolve_ref(&hub_path, &base_ref)?;

    let integration_branch = format!("orchestrator/integration/{run_id}");
    let final_branch = format!("orchestrator/final/{run_id}");

    let mut manifest = RunManifest {
        run_id: run_id.clone(),
        created_at: now_iso(),
        updated_at: now_iso(),
        repo_input: repo_input.clone(),
        repo_resolved: normalized_repo.clone(),
        repo_key: repo_key.clone(),
        hub_path: hub_path.to_string_lossy().to_string(),
        remote_name: "origin".to_string(),
        base_ref: base_ref.clone(),
        integration_branch: integration_branch.clone(),
        final_branch: final_branch.clone(),
        spec_path: spec_path.to_string_lossy().to_string(),
        agents: vec![],
        state: "running".to_string(),
        review: None,
        integration: None,
        published: None,
    };
    save_manifest(&manifest)?;

    let defaults = spec.defaults.clone().unwrap_or_default();
    let global_image = spec
        .image
        .clone()
        .unwrap_or_else(|| DEFAULT_IMAGE.to_string());

    for agent in &spec.agents {
        let agent_dir = run_dir.join("agents").join(&agent.name);
        let worktree = agent_dir.join("worktree");
        let out_dir = agent_dir.join("out");
        let log_path = agent_dir.join("docker.log");
        mkdirp(&out_dir)?;

        let agent_base_ref = agent.base_ref.clone().unwrap_or_else(|| base_ref.clone());
        resolve_ref(&hub_path, &agent_base_ref)?;
        let branch = format!("agent/{run_id}/{}", agent.name);
        let before_head =
            ensure_agent_branch_worktree(&hub_path, &agent_base_ref, &branch, &worktree)?;

        let image = agent.image.clone().unwrap_or_else(|| global_image.clone());
        let cpus = agent
            .cpus
            .clone()
            .or(defaults.cpus.clone())
            .unwrap_or_else(|| DEFAULT_CPUS.to_string());
        let memory = agent
            .memory
            .clone()
            .or(defaults.memory.clone())
            .unwrap_or_else(|| DEFAULT_MEMORY.to_string());
        let pids_limit = agent
            .pids_limit
            .or(defaults.pids_limit)
            .unwrap_or(DEFAULT_PIDS_LIMIT);
        let needs_network = agent
            .needs_network
            .or(defaults.needs_network)
            .unwrap_or(false);
        let read_only_rootfs = agent
            .read_only_rootfs
            .or(defaults.read_only_rootfs)
            .unwrap_or(false);
        let auto_commit = agent.auto_commit.or(defaults.auto_commit).unwrap_or(true);
        let commit_prefix = agent
            .commit_prefix
            .clone()
            .or(defaults.commit_prefix.clone())
            .unwrap_or_else(|| "agent".to_string());

        let mut env_map = HashMap::new();
        env_map.insert("AGENT_NAME".to_string(), agent.name.clone());
        env_map.insert("RUN_ID".to_string(), run_id.clone());
        env_map.insert("AGENT_BRANCH".to_string(), branch.clone());
        env_map.insert("AGENT_BASE_REF".to_string(), agent_base_ref.clone());
        for (k, v) in &agent.env {
            env_map.insert(k.clone(), v.clone());
        }

        let container_name = format!("agent-{run_id}-{}", sanitize_container_name(&agent.name));
        let docker_cmd = docker_command(DockerCmdOptions {
            container_name,
            image: image.clone(),
            cmd: agent.cmd.clone(),
            worktree: worktree.clone(),
            out_dir: out_dir.clone(),
            env_map,
            cpus,
            memory,
            pids_limit,
            needs_network,
            read_only_rootfs,
        })?;
        let exit_code = run_logged(&docker_cmd, &log_path, None)?;

        let commit_info = ensure_commit_if_needed(
            &worktree,
            &before_head,
            &agent.name,
            &commit_prefix,
            agent.commit_message.as_deref(),
            auto_commit,
        )?;

        let existing_result = read_result_json(&out_dir)?;
        let result_obj = normalized_result(
            &agent.name,
            exit_code,
            commit_info.committed,
            commit_info.dirty_uncommitted,
            existing_result,
        );
        write_json(&out_dir.join("result.json"), &result_obj)?;

        let status = result_obj
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let summary = result_obj
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        manifest.agents.push(AgentState {
            name: agent.name.clone(),
            branch,
            base_ref: agent_base_ref,
            before_head,
            after_head: commit_info.after_head,
            committed: commit_info.committed,
            auto_committed: commit_info.auto_committed,
            dirty_uncommitted: commit_info.dirty_uncommitted,
            exit_code,
            status,
            summary,
            worktree: worktree.to_string_lossy().to_string(),
            out_dir: out_dir.to_string_lossy().to_string(),
            log_path: log_path.to_string_lossy().to_string(),
            image,
            cmd: agent.cmd.clone(),
            needs_network,
            read_only_rootfs,
            required_checks: agent.required_checks.clone(),
        });
        manifest.updated_at = now_iso();
        save_manifest(&manifest)?;
    }

    manifest.state = "ran".to_string();
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;

    let agents: Vec<Value> = manifest
        .agents
        .iter()
        .map(|a| {
            json!({
                "name": a.name,
                "status": a.status,
                "exit_code": a.exit_code,
                "committed": a.committed,
                "branch": a.branch,
            })
        })
        .collect();
    print_json(&json!({
        "run_id": run_id,
        "state": manifest.state,
        "agents": agents,
    }))?;
    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    ensure_orch_dirs()?;
    if let Some(run_id) = &args.run_id {
        let manifest = repo_from_manifest(run_id)?;
        print_json(&serde_json::to_value(manifest)?)?;
        return Ok(());
    }
    let mut out = vec![];
    for run_id in list_runs()? {
        let m = repo_from_manifest(&run_id)?;
        out.push(json!({
            "run_id": run_id,
            "created_at": m.created_at,
            "updated_at": m.updated_at,
            "state": m.state,
            "repo_input": m.repo_input,
        }));
    }
    print_json(&Value::Array(out))?;
    Ok(())
}

fn cmd_logs(args: &LogsArgs) -> Result<()> {
    let manifest = repo_from_manifest(&args.run_id)?;
    let agent = manifest
        .agents
        .iter()
        .find(|a| a.name == args.agent)
        .ok_or_else(|| anyhow!("agent not found in run {}: {}", args.run_id, args.agent))?;
    let text = fs::read_to_string(&agent.log_path)
        .with_context(|| format!("log file not found: {}", agent.log_path))?;
    print!("{text}");
    Ok(())
}

fn cmd_review(args: &ReviewArgs) -> Result<()> {
    let mut manifest = repo_from_manifest(&args.run_id)?;
    let spec = load_spec(Path::new(&manifest.spec_path))?;
    let global_checks = spec
        .review
        .map(|r| r.required_checks)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !c.trim().is_empty())
        .collect::<Vec<_>>();

    let run_dir = runs_dir().join(&args.run_id);
    let review_dir = run_dir.join("review");
    mkdirp(&review_dir)?;

    let mut accepted = vec![];
    let mut skipped = vec![];
    let mut rejected = vec![];

    for agent in &manifest.agents {
        if agent.status == "no_change" {
            skipped.push(agent.name.clone());
            continue;
        }
        if agent.status == "failed" || agent.status == "blocked" {
            rejected.push(json!({
                "name": agent.name,
                "reason": format!("agent status is {}", agent.status)
            }));
            continue;
        }

        let mut checks = global_checks.clone();
        checks.extend(
            agent
                .required_checks
                .iter()
                .filter(|c| !c.trim().is_empty())
                .cloned(),
        );

        let mut failed_checks = vec![];
        if !checks.is_empty() {
            let log_path = review_dir.join(format!("{}.log", agent.name));
            let check_results = run_local_checks(Path::new(&agent.worktree), &checks, &log_path)?;
            for item in check_results {
                if item
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .unwrap_or(1)
                    != 0
                {
                    failed_checks.push(item);
                }
            }
            if !failed_checks.is_empty() {
                rejected.push(json!({
                    "name": agent.name,
                    "reason": "required checks failed",
                    "failed_checks": failed_checks,
                    "log_path": log_path.to_string_lossy().to_string(),
                }));
                continue;
            }
        }
        accepted.push(agent.name.clone());
    }

    let report = json!({
        "run_id": args.run_id,
        "created_at": now_iso(),
        "accepted": accepted,
        "rejected": rejected,
        "skipped": skipped,
        "required_checks": global_checks,
    });
    write_json(&review_dir.join("review.json"), &report)?;
    manifest.review = Some(report.clone());
    manifest.state = "reviewed".to_string();
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;
    print_json(&report)?;
    Ok(())
}

fn cmd_integrate(args: &IntegrateArgs) -> Result<()> {
    let mut manifest = repo_from_manifest(&args.run_id)?;
    let review = manifest
        .review
        .clone()
        .ok_or_else(|| anyhow!("review report missing; run 'normies review --run-id <id>' first"))?;

    let hub_path = PathBuf::from(&manifest.hub_path);
    let run_dir = runs_dir().join(&manifest.run_id);
    let integration_dir = run_dir.join("integration");
    let integration_wt = integration_dir.join("worktree");
    mkdirp(&integration_dir)?;

    remove_worktree_if_exists(&hub_path, &integration_wt)?;
    git_dir_cmd(
        &hub_path,
        &[
            "worktree".to_string(),
            "add".to_string(),
            "--detach".to_string(),
            integration_wt.to_string_lossy().to_string(),
            manifest.base_ref.clone(),
        ],
        true,
    )?;
    run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            integration_wt.to_string_lossy().to_string(),
            "checkout".to_string(),
            "-B".to_string(),
            manifest.integration_branch.clone(),
            manifest.base_ref.clone(),
        ],
        None,
        true,
        None,
    )?;

    let accepted_set: HashSet<String> = review
        .get("accepted")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut blocked = vec![];
    let mut merged = vec![];
    for agent in manifest
        .agents
        .iter()
        .filter(|a| accepted_set.contains(&a.name))
    {
        let worktree = Path::new(&agent.worktree);
        let rebase = run_cmd(
            vec![
                "git".to_string(),
                "-C".to_string(),
                worktree.to_string_lossy().to_string(),
                "rebase".to_string(),
                manifest.integration_branch.clone(),
            ],
            None,
            false,
            None,
        )?;
        if rebase.code != 0 {
            let _ = run_cmd(
                vec![
                    "git".to_string(),
                    "-C".to_string(),
                    worktree.to_string_lossy().to_string(),
                    "rebase".to_string(),
                    "--abort".to_string(),
                ],
                None,
                false,
                None,
            );
            blocked.push(json!({
                "name": agent.name,
                "branch": agent.branch,
                "reason": "rebase conflict or failure",
                "stderr": rebase.stderr.trim(),
                "stdout": rebase.stdout.trim(),
            }));
            continue;
        }

        let merge = run_cmd(
            vec![
                "git".to_string(),
                "-C".to_string(),
                integration_wt.to_string_lossy().to_string(),
                "merge".to_string(),
                "--ff-only".to_string(),
                agent.branch.clone(),
            ],
            None,
            false,
            None,
        )?;
        if merge.code != 0 {
            blocked.push(json!({
                "name": agent.name,
                "branch": agent.branch,
                "reason": "ff-only merge failed after rebase",
                "stderr": merge.stderr.trim(),
                "stdout": merge.stdout.trim(),
            }));
            continue;
        }
        merged.push(agent.name.clone());
    }

    let report = json!({
        "run_id": manifest.run_id,
        "created_at": now_iso(),
        "integration_branch": manifest.integration_branch,
        "base_ref": manifest.base_ref,
        "merged": merged,
        "blocked": blocked,
    });
    write_json(&integration_dir.join("integration.json"), &report)?;
    manifest.integration = Some(report.clone());
    manifest.state = if report
        .get("blocked")
        .and_then(Value::as_array)
        .map(|arr| arr.is_empty())
        .unwrap_or(true)
    {
        "integrated".to_string()
    } else {
        "integrated_with_blocks".to_string()
    };
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;
    print_json(&report)?;
    Ok(())
}

fn cmd_publish(args: &PublishArgs) -> Result<()> {
    let mut manifest = repo_from_manifest(&args.run_id)?;
    if manifest.integration.is_none() {
        bail!("integration report missing; run 'normies integrate --run-id <id>' first");
    }

    let hub_path = PathBuf::from(&manifest.hub_path);
    let remote_name = args
        .remote
        .clone()
        .unwrap_or_else(|| manifest.remote_name.clone());
    let final_branch = args
        .final_branch
        .clone()
        .unwrap_or_else(|| manifest.final_branch.clone());

    let push_ref = format!("{}:{final_branch}", manifest.integration_branch);
    let push = run_cmd(
        vec![
            "git".to_string(),
            "-c".to_string(),
            format!("remote.{remote_name}.mirror=false"),
            format!("--git-dir={}", hub_path.to_string_lossy()),
            "push".to_string(),
            remote_name.clone(),
            push_ref,
        ],
        None,
        false,
        None,
    )?;
    if push.code != 0 {
        bail!(
            "failed to push final branch {final_branch}\n{}",
            push.stderr.trim()
        );
    }

    let mut publish = Map::new();
    publish.insert("created_at".to_string(), Value::String(now_iso()));
    publish.insert("remote".to_string(), Value::String(remote_name.clone()));
    publish.insert(
        "integration_branch".to_string(),
        Value::String(manifest.integration_branch.clone()),
    );
    publish.insert("final_branch".to_string(), Value::String(final_branch.clone()));
    publish.insert("pushed".to_string(), Value::Bool(true));
    publish.insert("pr".to_string(), Value::Null);

    if args.final_pr {
        check_tool_exists("gh")?;
        let remote_url = run_cmd(
            vec![
                "git".to_string(),
                format!("--git-dir={}", hub_path.to_string_lossy()),
                "remote".to_string(),
                "get-url".to_string(),
                remote_name.clone(),
            ],
            None,
            true,
            None,
        )?
        .stdout
        .trim()
        .to_string();

        let owner_repo = parse_owner_repo_from_remote(&remote_url)
            .ok_or_else(|| anyhow!("could not infer GitHub owner/repo from remote URL"))?;
        let base_branch = args
            .base_branch
            .clone()
            .unwrap_or_else(|| manifest.base_ref.clone());
        let title = args
            .title
            .clone()
            .unwrap_or_else(|| format!("orchestrator: final changes for run {}", manifest.run_id));
        let merged = manifest
            .integration
            .as_ref()
            .and_then(|v| v.get("merged"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let merged_list = merged
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let blocked_count = manifest
            .integration
            .as_ref()
            .and_then(|v| v.get("blocked"))
            .and_then(Value::as_array)
            .map(|arr| arr.len())
            .unwrap_or(0);

        let body = format!(
            "Automated final PR for run `{}`.\n\n- Integration branch: `{}`\n- Final branch: `{}`\n- Base: `{}`\n- Merged agents: {}\n- Blocked agents: {}",
            manifest.run_id,
            manifest.integration_branch,
            final_branch,
            base_branch,
            if merged_list.is_empty() {
                "none".to_string()
            } else {
                merged_list
            },
            blocked_count
        );
        let pr = run_cmd(
            vec![
                "gh".to_string(),
                "pr".to_string(),
                "create".to_string(),
                "--repo".to_string(),
                owner_repo.clone(),
                "--head".to_string(),
                final_branch.clone(),
                "--base".to_string(),
                base_branch,
                "--title".to_string(),
                title,
                "--body".to_string(),
                body,
                "--draft".to_string(),
            ],
            None,
            false,
            None,
        )?;
        if pr.code != 0 {
            publish.insert(
                "pr".to_string(),
                json!({
                    "created": false,
                    "error": if !pr.stderr.trim().is_empty() { pr.stderr.trim() } else { pr.stdout.trim() }
                }),
            );
        } else {
            publish.insert(
                "pr".to_string(),
                json!({
                    "created": true,
                    "url": pr.stdout.trim(),
                    "repo": owner_repo
                }),
            );
        }
    }

    let publish_value = Value::Object(publish);
    manifest.published = Some(publish_value.clone());
    manifest.state = "published".to_string();
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;
    print_json(&publish_value)?;
    Ok(())
}

fn cmd_cleanup(args: &CleanupArgs) -> Result<()> {
    let manifest = repo_from_manifest(&args.run_id)?;
    let hub_path = PathBuf::from(&manifest.hub_path);
    let run_dir = runs_dir().join(&args.run_id);

    let integration_wt = run_dir.join("integration").join("worktree");
    if integration_wt.exists() {
        let _ = git_dir_cmd(
            &hub_path,
            &[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                integration_wt.to_string_lossy().to_string(),
            ],
            false,
        );
        let _ = fs::remove_dir_all(&integration_wt);
    }
    for agent in &manifest.agents {
        let wt = PathBuf::from(&agent.worktree);
        if wt.exists() {
            let _ = git_dir_cmd(
                &hub_path,
                &[
                    "worktree".to_string(),
                    "remove".to_string(),
                    "--force".to_string(),
                    wt.to_string_lossy().to_string(),
                ],
                false,
            );
            let _ = fs::remove_dir_all(&wt);
        }
    }
    if args.remove_run_dir {
        let _ = fs::remove_dir_all(&run_dir);
    }
    print_json(&json!({
        "run_id": args.run_id,
        "removed_worktrees": true,
        "removed_run_dir": args.remove_run_dir
    }))?;
    Ok(())
}

fn cmd_make_spec(args: &MakeSpecArgs) -> Result<()> {
    if args.agents.is_empty() {
        bail!("at least one --agent is required");
    }
    let network_set: HashSet<String> = args.network_agents.iter().cloned().collect();
    let mut agents = vec![];
    for raw in &args.agents {
        let (name, cmd) = parse_agent_entry(raw)?;
        let mut agent = Map::new();
        agent.insert("name".to_string(), Value::String(name.clone()));
        agent.insert("cmd".to_string(), Value::String(cmd));
        if network_set.contains(&name) {
            agent.insert("needs_network".to_string(), Value::Bool(true));
        }
        agents.push(Value::Object(agent));
    }

    let mut spec = Map::new();
    spec.insert("base_ref".to_string(), Value::String(args.base_ref.clone()));
    spec.insert("image".to_string(), Value::String(args.image.clone()));
    spec.insert(
        "defaults".to_string(),
        json!({
            "cpus": args.cpus,
            "memory": args.memory,
            "pids_limit": args.pids_limit,
            "needs_network": false,
            "auto_commit": args.auto_commit,
            "read_only_rootfs": false,
            "commit_prefix": "agent"
        }),
    );
    spec.insert(
        "review".to_string(),
        json!({
            "required_checks": args.checks
        }),
    );
    spec.insert("agents".to_string(), Value::Array(agents));
    if let Some(repo) = &args.repo {
        spec.insert("repo".to_string(), Value::String(repo.clone()));
    }

    if let Some(parent) = args.output.parent() {
        mkdirp(parent)?;
    }
    write_json(&args.output, &Value::Object(spec))?;
    println!("{}", args.output.canonicalize().unwrap_or(args.output.clone()).display());
    Ok(())
}

fn parse_agent_entry(raw: &str) -> Result<(String, String)> {
    let (name, cmd) = raw
        .split_once("::")
        .ok_or_else(|| anyhow!("agent must use format 'name::command'"))?;
    let name = name.trim();
    let cmd = cmd.trim();
    if name.is_empty() {
        bail!("agent name cannot be empty");
    }
    if cmd.is_empty() {
        bail!("agent command cannot be empty");
    }
    Ok((name.to_string(), cmd.to_string()))
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn orch_dir() -> PathBuf {
    std::env::var(ORCH_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".orchestrator"))
}

fn runs_dir() -> PathBuf {
    orch_dir().join("runs")
}

fn repos_dir() -> PathBuf {
    orch_dir().join("repos")
}

fn fake_docker_mode() -> bool {
    std::env::var(FAKE_DOCKER_ENV).ok().as_deref() == Some("1")
}

fn run_cmd(
    cmd: Vec<String>,
    cwd: Option<&Path>,
    check: bool,
    env_map: Option<&HashMap<String, String>>,
) -> Result<CmdOutput> {
    if cmd.is_empty() {
        bail!("empty command");
    }
    let mut command = Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    if let Some(map) = env_map {
        for (k, v) in map {
            command.env(k, v);
        }
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run command: {}", cmd.join(" ")))?;
    let code = output.status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if check && code != 0 {
        bail!(
            "command failed ({code}): {}\nstdout: {}\nstderr: {}",
            cmd.join(" "),
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(CmdOutput { code, stdout, stderr })
}

fn run_logged(cmd: &[String], logfile: &Path, cwd: Option<&Path>) -> Result<i32> {
    if fake_docker_mode() && cmd.first().map(String::as_str) == Some("docker") {
        return run_fake_docker(cmd, logfile);
    }
    if let Some(parent) = logfile.parent() {
        mkdirp(parent)?;
    }
    let out = run_cmd(cmd.to_vec(), cwd, false, None)?;
    let mut f = fs::File::create(logfile)?;
    writeln!(f, "$ {}", cmd.join(" "))?;
    if !out.stdout.is_empty() {
        write!(f, "{}", out.stdout)?;
    }
    if !out.stderr.is_empty() {
        write!(f, "{}", out.stderr)?;
    }
    writeln!(f, "\n[exit_code={}]", out.code)?;
    Ok(out.code)
}

fn run_fake_docker(cmd: &[String], logfile: &Path) -> Result<i32> {
    let mut worktree: Option<String> = None;
    let mut env_map: HashMap<String, String> = HashMap::new();
    let mut i = 0usize;
    while i < cmd.len() {
        if cmd[i] == "--mount" && i + 1 < cmd.len() {
            let mount = &cmd[i + 1];
            if mount.contains("dst=/work") {
                worktree = extract_mount_src(mount);
            }
        }
        if cmd[i] == "-e" && i + 1 < cmd.len() {
            if let Some((k, v)) = cmd[i + 1].split_once('=') {
                env_map.insert(k.to_string(), v.to_string());
            }
        }
        i += 1;
    }
    let worktree = worktree.ok_or_else(|| anyhow!("fake docker runner expected /work mount"))?;
    let shell_cmd = cmd
        .last()
        .ok_or_else(|| anyhow!("fake docker command missing shell payload"))?
        .to_string();
    let out = run_cmd(
        vec!["sh".to_string(), "-lc".to_string(), shell_cmd],
        Some(Path::new(&worktree)),
        false,
        Some(&env_map),
    )?;
    if let Some(parent) = logfile.parent() {
        mkdirp(parent)?;
    }
    let mut f = fs::File::create(logfile)?;
    if !out.stdout.is_empty() {
        write!(f, "{}", out.stdout)?;
    }
    if !out.stderr.is_empty() {
        write!(f, "{}", out.stderr)?;
    }
    writeln!(f, "\n[exit_code={}]", out.code)?;
    Ok(out.code)
}

fn extract_mount_src(mount: &str) -> Option<String> {
    for part in mount.split(',') {
        if let Some(src) = part.strip_prefix("src=") {
            return Some(src.to_string());
        }
    }
    None
}

fn check_tool_exists(tool: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {tool} >/dev/null 2>&1"))
        .status()
        .with_context(|| format!("failed to check PATH for {tool}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("required tool not found in PATH: {tool}")
    }
}

fn ensure_docker_daemon() -> Result<()> {
    if fake_docker_mode() {
        return Ok(());
    }
    let out = run_cmd(
        vec!["docker".to_string(), "info".to_string()],
        None,
        false,
        None,
    )?;
    if out.code == 0 {
        Ok(())
    } else {
        let detail = if !out.stderr.trim().is_empty() {
            out.stderr.trim().to_string()
        } else {
            out.stdout.trim().to_string()
        };
        bail!("docker daemon is not available: {detail}")
    }
}

fn ensure_orch_dirs() -> Result<()> {
    mkdirp(&runs_dir())?;
    mkdirp(&repos_dir())?;
    Ok(())
}

fn mkdirp(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        mkdirp(parent)?;
    }
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn load_spec(path: &Path) -> Result<Spec> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        serde_json::from_str(&text).context("invalid JSON spec")
    } else {
        serde_yaml::from_str(&text).context("invalid YAML spec")
    }
}

fn validate_spec(spec: &Spec) -> Result<()> {
    if spec.agents.is_empty() {
        bail!("spec must include non-empty 'agents' list");
    }
    let mut names = HashSet::new();
    for agent in &spec.agents {
        if agent.name.trim().is_empty() {
            bail!("agent.name is required");
        }
        if !names.insert(agent.name.clone()) {
            bail!("duplicate agent name: {}", agent.name);
        }
        if agent.cmd.trim().is_empty() {
            bail!("agent.cmd is required for {}", agent.name);
        }
    }
    Ok(())
}

fn sanitize_repo_key(repo: &str) -> String {
    let raw = if Path::new(repo).exists() {
        Path::new(repo)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("repo")
            .to_string()
    } else {
        repo.trim_end_matches('/')
            .split('/')
            .next_back()
            .unwrap_or("repo")
            .to_string()
    };
    let raw = raw.trim_end_matches(".git");
    let re = Regex::new(r"[^A-Za-z0-9._-]+").expect("valid regex");
    let cleaned = re.replace_all(raw, "_").to_string();
    if cleaned.is_empty() {
        "repo".to_string()
    } else {
        cleaned
    }
}

fn sanitize_container_name(name: &str) -> String {
    let re = Regex::new(r"[^a-zA-Z0-9_.-]+").expect("valid regex");
    re.replace_all(name, "-").to_string()
}

pub fn normalize_repo_input(repo: &str) -> Result<String> {
    let path = Path::new(repo);
    if path.exists() {
        return Ok(path.canonicalize()?.to_string_lossy().to_string());
    }
    let re = Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").expect("valid regex");
    if re.is_match(repo) {
        return Ok(format!("https://github.com/{repo}.git"));
    }
    Ok(repo.to_string())
}

fn ensure_hub(repo_input: &str, repo_key: &str) -> Result<PathBuf> {
    let hub_path = repos_dir().join(format!("{repo_key}.git"));
    if hub_path.exists() {
        run_cmd(
            vec![
                "git".to_string(),
                format!("--git-dir={}", hub_path.to_string_lossy()),
                "remote".to_string(),
                "update".to_string(),
                "--prune".to_string(),
            ],
            None,
            true,
            None,
        )?;
        return Ok(hub_path);
    }
    run_cmd(
        vec![
            "git".to_string(),
            "clone".to_string(),
            "--mirror".to_string(),
            repo_input.to_string(),
            hub_path.to_string_lossy().to_string(),
        ],
        None,
        true,
        None,
    )?;
    Ok(hub_path)
}

fn create_run_id() -> String {
    let stamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let mut rng = rand::thread_rng();
    let mut suffix = String::new();
    for _ in 0..6 {
        suffix.push_str(&format!("{:x}", rng.gen_range(0..16)));
    }
    format!("{stamp}-{suffix}")
}

fn git_dir_cmd(git_dir: &Path, args: &[String], check: bool) -> Result<CmdOutput> {
    let mut cmd = vec![format!("--git-dir={}", git_dir.to_string_lossy())];
    cmd.extend_from_slice(args);
    let mut full = vec!["git".to_string()];
    full.extend(cmd);
    run_cmd(full, None, check, None)
}

fn resolve_ref(git_dir: &Path, reference: &str) -> Result<String> {
    let out = git_dir_cmd(
        git_dir,
        &[
            "rev-parse".to_string(),
            "--verify".to_string(),
            format!("{reference}^{{commit}}"),
        ],
        true,
    )?;
    Ok(out.stdout.trim().to_string())
}

fn remove_worktree_if_exists(git_dir: &Path, worktree: &Path) -> Result<()> {
    if worktree.exists() {
        let _ = git_dir_cmd(
            git_dir,
            &[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                worktree.to_string_lossy().to_string(),
            ],
            false,
        );
        let _ = fs::remove_dir_all(worktree);
    }
    Ok(())
}

fn ensure_agent_branch_worktree(
    git_dir: &Path,
    base_ref: &str,
    branch: &str,
    worktree: &Path,
) -> Result<String> {
    remove_worktree_if_exists(git_dir, worktree)?;
    if let Some(parent) = worktree.parent() {
        mkdirp(parent)?;
    }
    git_dir_cmd(
        git_dir,
        &[
            "worktree".to_string(),
            "add".to_string(),
            "--detach".to_string(),
            worktree.to_string_lossy().to_string(),
            base_ref.to_string(),
        ],
        true,
    )?;
    run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.to_string_lossy().to_string(),
            "checkout".to_string(),
            "-B".to_string(),
            branch.to_string(),
            base_ref.to_string(),
        ],
        None,
        true,
        None,
    )?;
    git_head(worktree)
}

struct DockerCmdOptions {
    container_name: String,
    image: String,
    cmd: String,
    worktree: PathBuf,
    out_dir: PathBuf,
    env_map: HashMap<String, String>,
    cpus: String,
    memory: String,
    pids_limit: i64,
    needs_network: bool,
    read_only_rootfs: bool,
}

fn current_uid_gid() -> (String, String) {
    let uid = run_cmd(
        vec!["id".to_string(), "-u".to_string()],
        None,
        false,
        None,
    )
    .map(|o| o.stdout.trim().to_string())
    .unwrap_or_else(|_| "0".to_string());
    let gid = run_cmd(
        vec!["id".to_string(), "-g".to_string()],
        None,
        false,
        None,
    )
    .map(|o| o.stdout.trim().to_string())
    .unwrap_or_else(|_| "0".to_string());
    (uid, gid)
}

fn docker_command(opts: DockerCmdOptions) -> Result<Vec<String>> {
    let (uid, gid) = current_uid_gid();
    let mut cmd = vec![
        "docker".to_string(),
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        opts.container_name,
        "--workdir".to_string(),
        "/work".to_string(),
        "--user".to_string(),
        format!("{uid}:{gid}"),
        "--cpus".to_string(),
        opts.cpus,
        "--memory".to_string(),
        opts.memory,
        "--pids-limit".to_string(),
        opts.pids_limit.to_string(),
        "--mount".to_string(),
        format!(
            "type=bind,src={},dst=/work,rw",
            opts.worktree.canonicalize()?.to_string_lossy()
        ),
        "--mount".to_string(),
        format!(
            "type=bind,src={},dst=/out,rw",
            opts.out_dir.canonicalize()?.to_string_lossy()
        ),
    ];
    if !opts.needs_network {
        cmd.push("--network".to_string());
        cmd.push("none".to_string());
    }
    if opts.read_only_rootfs {
        cmd.push("--read-only".to_string());
        cmd.push("--tmpfs".to_string());
        cmd.push("/tmp".to_string());
        cmd.push("--tmpfs".to_string());
        cmd.push("/run".to_string());
    }
    for (k, v) in opts.env_map {
        cmd.push("-e".to_string());
        cmd.push(format!("{k}={v}"));
    }
    cmd.push(opts.image);
    cmd.push("sh".to_string());
    cmd.push("-lc".to_string());
    cmd.push(opts.cmd);
    Ok(cmd)
}

fn git_is_dirty(worktree: &Path) -> Result<bool> {
    let out = run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.to_string_lossy().to_string(),
            "status".to_string(),
            "--porcelain".to_string(),
        ],
        None,
        true,
        None,
    )?;
    Ok(!out.stdout.trim().is_empty())
}

fn git_head(worktree: &Path) -> Result<String> {
    let out = run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.to_string_lossy().to_string(),
            "rev-parse".to_string(),
            "HEAD".to_string(),
        ],
        None,
        true,
        None,
    )?;
    Ok(out.stdout.trim().to_string())
}

pub fn ensure_commit_if_needed(
    worktree: &Path,
    before_head: &str,
    agent_name: &str,
    commit_prefix: &str,
    commit_message: Option<&str>,
    auto_commit: bool,
) -> Result<CommitInfo> {
    let changed = git_is_dirty(worktree)?;
    if !changed {
        return Ok(CommitInfo {
            committed: git_head(worktree)? != before_head,
            auto_committed: false,
            dirty_uncommitted: false,
            after_head: git_head(worktree)?,
        });
    }
    if !auto_commit {
        return Ok(CommitInfo {
            committed: git_head(worktree)? != before_head,
            auto_committed: false,
            dirty_uncommitted: true,
            after_head: git_head(worktree)?,
        });
    }

    let message = commit_message
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{commit_prefix}({agent_name}): apply automated changes"));
    run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.to_string_lossy().to_string(),
            "add".to_string(),
            "-A".to_string(),
        ],
        None,
        true,
        None,
    )?;
    run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            worktree.to_string_lossy().to_string(),
            "-c".to_string(),
            format!("user.name={agent_name}"),
            "-c".to_string(),
            format!("user.email={agent_name}@local.agent"),
            "commit".to_string(),
            "-m".to_string(),
            message,
        ],
        None,
        true,
        None,
    )?;
    Ok(CommitInfo {
        committed: git_head(worktree)? != before_head,
        auto_committed: true,
        dirty_uncommitted: false,
        after_head: git_head(worktree)?,
    })
}

fn read_result_json(out_dir: &Path) -> Result<Option<Value>> {
    let p = out_dir.join("result.json");
    if !p.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&p)?;
    let value: Value = serde_json::from_str(&text).context("invalid result.json")?;
    if value.is_object() {
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub fn normalized_result(
    agent_name: &str,
    exit_code: i32,
    committed: bool,
    dirty_uncommitted: bool,
    existing: Option<Value>,
) -> Value {
    let mut result = existing
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();

    if exit_code != 0 {
        result.insert("status".to_string(), Value::String("failed".to_string()));
        if !result.contains_key("summary") {
            result.insert(
                "summary".to_string(),
                Value::String(format!("agent {agent_name} failed")),
            );
        }
    } else if dirty_uncommitted {
        result.insert("status".to_string(), Value::String("blocked".to_string()));
        if !result.contains_key("summary") {
            result.insert(
                "summary".to_string(),
                Value::String(format!(
                    "agent {agent_name} left uncommitted changes (set auto_commit=true or commit in-agent)"
                )),
            );
        }
    } else if !result.contains_key("status") {
        result.insert(
            "status".to_string(),
            Value::String(if committed { "ok" } else { "no_change" }.to_string()),
        );
        result.insert(
            "summary".to_string(),
            Value::String(format!("agent {agent_name} completed")),
        );
    }

    if !result.contains_key("checks") {
        result.insert("checks".to_string(), Value::Array(vec![]));
    }
    if !result.contains_key("artifacts") {
        result.insert("artifacts".to_string(), Value::Array(vec![]));
    }
    if !result.contains_key("metrics") {
        result.insert("metrics".to_string(), Value::Object(Map::new()));
    }
    if !result.contains_key("summary") {
        result.insert(
            "summary".to_string(),
            Value::String(format!("agent {agent_name} completed")),
        );
    }
    if !result.contains_key("status") {
        result.insert("status".to_string(), Value::String("no_change".to_string()));
    }
    Value::Object(result)
}

fn save_manifest(manifest: &RunManifest) -> Result<()> {
    let path = runs_dir().join(&manifest.run_id).join("run.json");
    write_json(&path, &serde_json::to_value(manifest)?)
}

fn repo_from_manifest(run_id: &str) -> Result<RunManifest> {
    let path = runs_dir().join(run_id).join("run.json");
    let text = fs::read_to_string(&path).with_context(|| format!("run not found: {run_id}"))?;
    serde_json::from_str(&text).with_context(|| format!("invalid run manifest: {}", path.display()))
}

fn list_runs() -> Result<Vec<String>> {
    let dir = runs_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn run_local_checks(worktree: &Path, commands: &[String], log_path: &Path) -> Result<Vec<Value>> {
    if let Some(parent) = log_path.parent() {
        mkdirp(parent)?;
    }
    let mut file = fs::File::create(log_path)?;
    let mut out = vec![];
    for command in commands {
        writeln!(file, "$ {command}")?;
        let res = run_cmd(
            vec!["sh".to_string(), "-lc".to_string(), command.clone()],
            Some(worktree),
            false,
            None,
        )?;
        if !res.stdout.is_empty() {
            write!(file, "{}", res.stdout)?;
        }
        if !res.stderr.is_empty() {
            write!(file, "{}", res.stderr)?;
        }
        writeln!(file, "\n[exit_code={}]\n", res.code)?;
        out.push(json!({
            "command": command,
            "exit_code": res.code,
            "status": if res.code == 0 { "pass" } else { "fail" }
        }));
    }
    Ok(out)
}

pub fn parse_owner_repo_from_remote(remote_url: &str) -> Option<String> {
    let re = Regex::new(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?$").ok()?;
    let caps = re.captures(remote_url)?;
    let owner = caps.get(1)?.as_str();
    let repo = caps.get(2)?.as_str();
    Some(format!("{owner}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_slug_to_https() {
        let got = normalize_repo_input("owner/repo").expect("normalize");
        assert_eq!(got, "https://github.com/owner/repo.git");
    }

    #[test]
    fn parse_owner_repo() {
        assert_eq!(
            parse_owner_repo_from_remote("https://github.com/acme/proj.git"),
            Some("acme/proj".to_string())
        );
        assert_eq!(
            parse_owner_repo_from_remote("git@github.com:acme/proj.git"),
            Some("acme/proj".to_string())
        );
        assert_eq!(
            parse_owner_repo_from_remote("https://example.com/acme/proj.git"),
            None
        );
    }

    #[test]
    fn failed_exit_overrides_existing_ok() {
        let out = normalized_result(
            "a1",
            9,
            true,
            false,
            Some(json!({"status": "ok", "summary": "done"})),
        );
        assert_eq!(out.get("status").and_then(Value::as_str), Some("failed"));
    }
}
