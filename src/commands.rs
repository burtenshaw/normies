use anyhow::{Context, Result, anyhow, bail};
use rand::Rng;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::cli::{
    CleanupArgs, Commands, DEFAULT_BASE_REF, DEFAULT_CPUS, DEFAULT_IMAGE, DEFAULT_MEMORY,
    DEFAULT_PIDS_LIMIT, DoctorArgs, InitArgs, IntegrateArgs, LogsArgs, MakeSpecArgs, RetryArgs,
    ReviewArgs, RunArgs, StatusArgs,
};
use crate::gateway::{GatewayHandle, GatewayStartAgent, GatewayStartOptions, start_gateway};
use crate::models::{
    A2aGatewayConfig, AgentSpec, AgentState, GatewayTelemetry, PreparedAgent, ReviewConfig,
    RunManifest, Spec, SpecDefaults,
};
use crate::runtime::{
    DockerCmdOptions, check_tool_exists, create_run_id, docker_command,
    ensure_agent_branch_worktree, ensure_commit_if_needed, ensure_docker_daemon, ensure_hub,
    ensure_orch_dirs, fake_docker_mode, git_dir_cmd, git_head, git_is_dirty, list_runs, load_spec,
    mkdirp, normalize_repo_input, normalized_result, now_iso, orch_dir, parse_agent_entry,
    print_json, read_result_json, remove_worktree_if_exists, repo_from_manifest, resolve_ref,
    run_cmd, run_local_checks, run_logged, runs_dir, sanitize_container_name, sanitize_repo_key,
    save_manifest, validate_spec, write_json,
};

pub fn execute(command: Commands) -> Result<()> {
    match command {
        Commands::Run(args) => cmd_run(&args),
        Commands::Retry(args) => cmd_retry(&args),
        Commands::Status(args) => cmd_status(&args),
        Commands::Logs(args) => cmd_logs(&args),
        Commands::Review(args) => cmd_review(&args),
        Commands::Integrate(args) => cmd_integrate(&args),
        Commands::Cleanup(args) => cmd_cleanup(&args),
        Commands::Doctor(args) => cmd_doctor(&args),
        Commands::Init(args) => cmd_init(&args),
        Commands::MakeSpec(args) => cmd_make_spec(&args),
    }
}

fn ensure_run_prereqs() -> Result<()> {
    check_tool_exists("git")?;
    if !fake_docker_mode() {
        check_tool_exists("docker")?;
    }
    ensure_docker_daemon()?;
    ensure_orch_dirs()?;
    Ok(())
}

fn cmd_run(args: &RunArgs) -> Result<()> {
    if args.jobs < 1 {
        bail!("--jobs must be >= 1");
    }
    ensure_run_prereqs()?;

    let spec_path = args.spec.canonicalize().context("spec file not found")?;
    let spec = load_spec(&spec_path)?;
    validate_spec(&spec)?;

    let repo_input = args
        .repo
        .clone()
        .or(spec.repo.clone())
        .ok_or_else(|| anyhow!("repo must be provided via --repo or spec.repo"))?;

    let base_ref = spec
        .base_ref
        .clone()
        .unwrap_or_else(|| DEFAULT_BASE_REF.to_string());

    let normalized_repo = normalize_repo_input(&repo_input)?;
    let repo_key = sanitize_repo_key(&normalized_repo);
    let hub_path = ensure_hub(&normalized_repo, &repo_key, &base_ref)?;

    let run_id = args.run_id.clone().unwrap_or_else(create_run_id);
    let run_dir = runs_dir().join(&run_id);
    if run_dir.exists() {
        bail!("run_id already exists: {run_id}");
    }
    mkdirp(&run_dir.join("agents"))?;

    resolve_ref(&hub_path, &base_ref)?;

    let integration_branch = format!("orchestrator/integration/{run_id}");

    let mut manifest = RunManifest {
        run_id: run_id.clone(),
        created_at: now_iso(),
        updated_at: now_iso(),
        repo_input: repo_input.clone(),
        repo_resolved: normalized_repo,
        repo_key,
        hub_path: hub_path.to_string_lossy().to_string(),
        base_ref: base_ref.clone(),
        integration_branch,
        spec_path: spec_path.to_string_lossy().to_string(),
        agents: vec![],
        state: "running".to_string(),
        review: None,
        integration: None,
        gateway: None,
    };
    save_manifest(&manifest)?;

    let defaults = spec.defaults.clone().unwrap_or_default();
    let global_image = spec
        .image
        .clone()
        .unwrap_or_else(|| DEFAULT_IMAGE.to_string());

    let selected_agents: Vec<&AgentSpec> = spec.agents.iter().collect();
    let gateway_ctx = prepare_gateway_context(&spec, &selected_agents, &run_dir)?;

    let prepare_ctx = PrepareContext {
        run_id: &run_id,
        run_dir: &run_dir,
        hub_path: &hub_path,
        base_ref: &base_ref,
        defaults: &defaults,
        global_image: &global_image,
        gateway: gateway_ctx.as_ref().map(|ctx| GatewayPrepareContext {
            gateway_dir: &ctx.gateway_dir,
            token_by_agent: &ctx.token_by_agent,
            peers_json_by_agent: &ctx.peers_json_by_agent,
        }),
    };

    let mut resolved_refs: HashSet<String> = HashSet::new();
    resolved_refs.insert(base_ref.clone());
    let mut prepared = Vec::with_capacity(spec.agents.len());
    for agent in &spec.agents {
        let agent_base_ref = agent.base_ref.as_deref().unwrap_or(&base_ref);
        resolve_ref_once(&hub_path, agent_base_ref, &mut resolved_refs)?;
        prepared.push(prepare_agent(&prepare_ctx, agent, None)?);
    }

    let mut gateway_handle = if let Some(ctx) = gateway_ctx.as_ref() {
        let handle = start_gateway(GatewayStartOptions {
            run_id: run_id.clone(),
            socket_path: ctx.gateway_socket_host.clone(),
            log_path: ctx.gateway_log_path.clone(),
            bind_timeout_ms: ctx.config.bind_timeout_ms,
            request_timeout_ms: ctx.config.request_timeout_ms,
            stream_idle_timeout_ms: ctx.config.stream_idle_timeout_ms,
            max_payload_bytes: ctx.config.max_payload_bytes,
            token_by_agent: ctx.token_by_agent.clone(),
            agents: ctx.start_agents.clone(),
        })?;
        manifest.gateway = Some(handle.startup_telemetry());
        Some(handle)
    } else {
        None
    };

    let execute_result = execute_prepared_agents(prepared, args.jobs, !args.json);
    manifest.gateway = stop_gateway(gateway_handle.as_mut(), manifest.gateway.as_ref())?;
    manifest.agents = execute_result?;
    manifest.state = "ran".to_string();
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;

    if args.json {
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
                    "worktree": a.worktree,
                    "out_dir": a.out_dir,
                    "log_path": a.log_path,
                    "summary": a.summary,
                    "dirty_uncommitted": a.dirty_uncommitted,
                })
            })
            .collect();
        print_json(&json!({
            "run_id": run_id,
            "state": manifest.state,
            "jobs": args.jobs,
            "run_dir": run_dir.to_string_lossy().to_string(),
            "manifest_path": run_dir.join("run.json").to_string_lossy().to_string(),
            "agents": agents,
            "gateway": manifest.gateway,
        }))?;
        return Ok(());
    }

    println!("Run {} completed (jobs={})", manifest.run_id, args.jobs);
    print_agent_summary(&manifest.agents);
    println!("Next: normies review --run-id {}", manifest.run_id);
    Ok(())
}

fn cmd_retry(args: &RetryArgs) -> Result<()> {
    if args.jobs < 1 {
        bail!("--jobs must be >= 1");
    }
    if !args.failed {
        bail!("at least one selector is required; try --failed");
    }

    ensure_run_prereqs()?;

    let mut manifest = load_manifest_for_run(&args.run_id)?;
    let spec = load_spec(Path::new(&manifest.spec_path))?;
    validate_spec(&spec)?;

    let selected: HashSet<String> = manifest
        .agents
        .iter()
        .filter(|a| a.status == "failed")
        .map(|a| a.name.clone())
        .collect();

    if selected.is_empty() {
        if args.json {
            print_json(&json!({
                "run_id": manifest.run_id,
                "state": manifest.state,
                "retried": [],
                "message": "no failed agents to retry",
            }))?;
        } else {
            println!("No failed agents to retry for run {}", manifest.run_id);
        }
        return Ok(());
    }

    let spec_names: HashSet<String> = spec.agents.iter().map(|a| a.name.clone()).collect();
    for name in &selected {
        if !spec_names.contains(name) {
            bail!("cannot retry agent '{name}': present in manifest but missing from current spec");
        }
    }

    let run_dir = runs_dir().join(&manifest.run_id);
    let hub_path = PathBuf::from(&manifest.hub_path);
    let defaults = spec.defaults.clone().unwrap_or_default();
    let global_image = spec
        .image
        .clone()
        .unwrap_or_else(|| DEFAULT_IMAGE.to_string());

    let existing_by_name: HashMap<String, AgentState> = manifest
        .agents
        .iter()
        .cloned()
        .map(|a| (a.name.clone(), a))
        .collect();

    let selected_agents: Vec<&AgentSpec> = spec
        .agents
        .iter()
        .filter(|agent| selected.contains(&agent.name))
        .collect();
    let gateway_ctx = prepare_gateway_context(&spec, &selected_agents, &run_dir)?;

    let prepare_ctx = PrepareContext {
        run_id: &manifest.run_id,
        run_dir: &run_dir,
        hub_path: &hub_path,
        base_ref: &manifest.base_ref,
        defaults: &defaults,
        global_image: &global_image,
        gateway: gateway_ctx.as_ref().map(|ctx| GatewayPrepareContext {
            gateway_dir: &ctx.gateway_dir,
            token_by_agent: &ctx.token_by_agent,
            peers_json_by_agent: &ctx.peers_json_by_agent,
        }),
    };

    let mut resolved_refs: HashSet<String> = HashSet::new();
    let mut prepared = vec![];
    for agent in &spec.agents {
        if !selected.contains(&agent.name) {
            continue;
        }
        let agent_base_ref = agent.base_ref.as_deref().unwrap_or(&manifest.base_ref);
        resolve_ref_once(&hub_path, agent_base_ref, &mut resolved_refs)?;
        let branch_override = existing_by_name.get(&agent.name).map(|a| a.branch.as_str());
        prepared.push(prepare_agent(&prepare_ctx, agent, branch_override)?);
    }

    let mut gateway_handle = if let Some(ctx) = gateway_ctx.as_ref() {
        let handle = start_gateway(GatewayStartOptions {
            run_id: manifest.run_id.clone(),
            socket_path: ctx.gateway_socket_host.clone(),
            log_path: ctx.gateway_log_path.clone(),
            bind_timeout_ms: ctx.config.bind_timeout_ms,
            request_timeout_ms: ctx.config.request_timeout_ms,
            stream_idle_timeout_ms: ctx.config.stream_idle_timeout_ms,
            max_payload_bytes: ctx.config.max_payload_bytes,
            token_by_agent: ctx.token_by_agent.clone(),
            agents: ctx.start_agents.clone(),
        })?;
        manifest.gateway = Some(handle.startup_telemetry());
        Some(handle)
    } else {
        None
    };

    let rerun_result = execute_prepared_agents(prepared, args.jobs, !args.json);
    manifest.gateway = stop_gateway(gateway_handle.as_mut(), manifest.gateway.as_ref())?;
    let rerun_states = rerun_result?;

    let mut merged_by_name = existing_by_name;
    for state in &rerun_states {
        merged_by_name.insert(state.name.clone(), state.clone());
    }

    let mut ordered_agents = Vec::with_capacity(merged_by_name.len());
    for agent in &spec.agents {
        if let Some(state) = merged_by_name.remove(&agent.name) {
            ordered_agents.push(state);
        }
    }
    for (_, state) in merged_by_name {
        ordered_agents.push(state);
    }

    manifest.agents = ordered_agents;
    manifest.review = None;
    manifest.integration = None;
    manifest.state = "ran".to_string();
    manifest.updated_at = now_iso();
    save_manifest(&manifest)?;

    if args.json {
        let retried: Vec<Value> = rerun_states
            .iter()
            .map(|a| {
                json!({
                    "name": a.name,
                    "status": a.status,
                    "exit_code": a.exit_code,
                    "committed": a.committed,
                    "branch": a.branch,
                    "worktree": a.worktree,
                    "out_dir": a.out_dir,
                    "log_path": a.log_path,
                    "summary": a.summary,
                    "dirty_uncommitted": a.dirty_uncommitted,
                })
            })
            .collect();
        print_json(&json!({
            "run_id": manifest.run_id,
            "state": manifest.state,
            "jobs": args.jobs,
            "run_dir": run_dir.to_string_lossy().to_string(),
            "manifest_path": run_dir.join("run.json").to_string_lossy().to_string(),
            "retried": retried,
            "gateway": manifest.gateway,
        }))?;
        return Ok(());
    }

    println!(
        "Retried {} failed agent(s) for run {} (jobs={})",
        rerun_states.len(),
        manifest.run_id,
        args.jobs
    );
    print_agent_summary(&rerun_states);
    println!("Next: normies review --run-id {}", manifest.run_id);
    Ok(())
}

fn cmd_status(args: &StatusArgs) -> Result<()> {
    ensure_orch_dirs()?;

    if args.run_id.is_some() && args.latest {
        bail!("use either --run-id or --latest, not both");
    }

    if let Some(run_id) = &args.run_id {
        let manifest = load_manifest_for_run(run_id)?;
        return print_status_detail(&manifest, args.json);
    }

    if args.latest {
        let run_id = latest_run_id()?;
        let manifest = load_manifest_for_run(&run_id)?;
        return print_status_detail(&manifest, args.json);
    }

    let mut summaries = vec![];
    for run_id in list_runs()? {
        let m = load_manifest_for_run(&run_id)?;
        summaries.push(json!({
            "run_id": run_id,
            "created_at": m.created_at,
            "updated_at": m.updated_at,
            "state": m.state,
            "repo_input": m.repo_input,
        }));
    }

    if args.json {
        print_json(&Value::Array(summaries))?;
        return Ok(());
    }

    if summaries.is_empty() {
        println!("No runs found.");
        println!("Start one with: normies run --repo <repo> --spec <spec>");
        return Ok(());
    }

    println!("Recent runs:");
    for item in summaries.iter().rev() {
        let run_id = item.get("run_id").and_then(Value::as_str).unwrap_or("-");
        let state = item.get("state").and_then(Value::as_str).unwrap_or("-");
        let updated = item
            .get("updated_at")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let repo_input = item
            .get("repo_input")
            .and_then(Value::as_str)
            .unwrap_or("-");
        println!(
            "- {:<20} {:<22} {:<22} {}",
            run_id, state, updated, repo_input
        );
    }
    println!("Tip: use --latest for the most recent run.");
    Ok(())
}

fn print_status_detail(manifest: &RunManifest, json_out: bool) -> Result<()> {
    let run_dir = runs_dir().join(&manifest.run_id);
    let manifest_path = run_dir.join("run.json");
    let worktree_status = collect_worktree_status(manifest, &run_dir);

    if json_out {
        let mut payload = serde_json::to_value(manifest)?;
        if let Value::Object(map) = &mut payload {
            map.insert(
                "run_dir".to_string(),
                Value::String(run_dir.to_string_lossy().to_string()),
            );
            map.insert(
                "manifest_path".to_string(),
                Value::String(manifest_path.to_string_lossy().to_string()),
            );
            map.insert("worktree_status".to_string(), worktree_status);
        }
        print_json(&payload)?;
        return Ok(());
    }

    println!("Run {}", manifest.run_id);
    println!("State: {}", manifest.state);
    println!("Repo: {}", manifest.repo_input);
    println!("Base ref: {}", manifest.base_ref);
    println!("Integration branch: {}", manifest.integration_branch);
    println!("Run dir: {}", run_dir.display());
    println!("Manifest: {}", manifest_path.display());
    println!("Created: {}", manifest.created_at);
    println!("Updated: {}", manifest.updated_at);
    if let Some(gateway) = &manifest.gateway {
        println!(
            "Gateway: enabled={} transport={} socket={}",
            if gateway.enabled { "yes" } else { "no" },
            gateway.transport,
            gateway.socket_path
        );
    }
    println!();
    print_agent_summary(&manifest.agents);
    println!();
    println!("Worktrees:");
    let integration = worktree_status
        .get("integration")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let integration_path = integration
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("-");
    let integration_exists = integration
        .get("exists")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let integration_dirty = integration
        .get("dirty")
        .and_then(Value::as_bool)
        .map(bool_word)
        .unwrap_or("-");
    println!(
        "- integration exists={} dirty={} path={}",
        if integration_exists { "yes" } else { "no" },
        integration_dirty,
        integration_path
    );
    if let Some(items) = worktree_status.get("agents").and_then(Value::as_array) {
        for item in items {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let exists = item.get("exists").and_then(Value::as_bool).unwrap_or(false);
            let dirty = item
                .get("dirty")
                .and_then(Value::as_bool)
                .map(bool_word)
                .unwrap_or("-");
            let path = item.get("path").and_then(Value::as_str).unwrap_or("-");
            println!(
                "- {} exists={} dirty={} path={}",
                name,
                if exists { "yes" } else { "no" },
                dirty,
                path
            );
        }
    }

    match manifest.state.as_str() {
        "ran" => println!("Next: normies review --run-id {}", manifest.run_id),
        "reviewed" => println!("Next: normies integrate --run-id {}", manifest.run_id),
        "integrated" | "integrated_with_blocks" => {
            println!(
                "Fetch: git fetch {} {}",
                manifest.hub_path, manifest.integration_branch
            );
            println!("Merge: git merge --ff-only FETCH_HEAD");
            println!(
                "Push: git --git-dir {} push origin {}",
                manifest.hub_path, manifest.integration_branch
            );
            println!("Next: normies cleanup --run-id {}", manifest.run_id);
        }
        _ => {}
    }
    Ok(())
}

fn collect_worktree_status(manifest: &RunManifest, run_dir: &Path) -> Value {
    let integration_wt = run_dir.join("integration").join("worktree");
    let agents = manifest
        .agents
        .iter()
        .map(|agent| {
            let wt = PathBuf::from(&agent.worktree);
            let mut item = inspect_worktree(&wt);
            if let Value::Object(map) = &mut item {
                map.insert("name".to_string(), Value::String(agent.name.clone()));
                map.insert("status".to_string(), Value::String(agent.status.clone()));
                map.insert("branch".to_string(), Value::String(agent.branch.clone()));
            }
            item
        })
        .collect::<Vec<_>>();
    json!({
        "integration": inspect_worktree(&integration_wt),
        "agents": agents
    })
}

fn inspect_worktree(path: &Path) -> Value {
    let exists = path.exists();
    let head = if exists { git_head(path).ok() } else { None };
    let dirty = if exists {
        git_is_dirty(path).ok()
    } else {
        None
    };
    json!({
        "path": path.to_string_lossy().to_string(),
        "exists": exists,
        "head": head,
        "dirty": dirty
    })
}

fn bool_word(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn cmd_logs(args: &LogsArgs) -> Result<()> {
    let run_id = resolve_run_id(args.run_id.as_deref(), args.latest, true)?;
    let manifest = load_manifest_for_run(&run_id)?;

    if args.list_agents {
        if manifest.agents.is_empty() {
            println!("Run {} has no agents.", run_id);
            return Ok(());
        }
        println!("Agents for run {}:", run_id);
        for agent in &manifest.agents {
            println!("- {} ({})", agent.name, agent.status);
        }
        return Ok(());
    }

    let agent_name = args.agent.clone().ok_or_else(|| {
        let names = manifest
            .agents
            .iter()
            .map(|a| a.name.clone())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow!(
            "agent is required. use --agent <name> or --list-agents. available: {}",
            if names.is_empty() { "none" } else { &names }
        )
    })?;

    let agent = manifest
        .agents
        .iter()
        .find(|a| a.name == agent_name)
        .ok_or_else(|| {
            let names = manifest
                .agents
                .iter()
                .map(|a| a.name.clone())
                .collect::<Vec<_>>()
                .join(", ");
            anyhow!(
                "agent not found in run {}: {}. available agents: {}",
                run_id,
                agent_name,
                if names.is_empty() { "none" } else { &names }
            )
        })?;

    let text = fs::read_to_string(&agent.log_path)
        .with_context(|| format!("log file not found: {}", agent.log_path))?;

    if let Some(tail) = args.tail {
        print_tail(&text, tail);
    } else {
        print!("{text}");
    }

    if args.follow {
        let mut offset = fs::metadata(&agent.log_path)
            .with_context(|| format!("log file not found: {}", agent.log_path))?
            .len();

        loop {
            let mut file = fs::File::open(&agent.log_path)
                .with_context(|| format!("log file not found: {}", agent.log_path))?;
            let len = file.metadata()?.len();
            if len < offset {
                offset = 0;
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = String::new();
            let read = file.read_to_string(&mut buf)?;
            if read > 0 {
                print!("{buf}");
                std::io::stdout().flush()?;
                offset += read as u64;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    Ok(())
}

fn print_tail(text: &str, tail: usize) {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(tail);
    if start >= lines.len() {
        print!("{text}");
        return;
    }

    let mut out = lines[start..].join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    print!("{out}");
}

fn cmd_review(args: &ReviewArgs) -> Result<()> {
    let run_id = resolve_run_id(args.run_id.as_deref(), args.latest, true)?;
    let mut manifest = load_manifest_for_run(&run_id)?;
    let spec = load_spec(Path::new(&manifest.spec_path))?;
    validate_spec(&spec)?;

    let global_checks = spec
        .review
        .map(|r| r.required_checks)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !c.trim().is_empty())
        .collect::<Vec<_>>();

    let run_dir = runs_dir().join(&run_id);
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
                if item.get("exit_code").and_then(Value::as_i64).unwrap_or(1) != 0 {
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
        "run_id": run_id,
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

    if args.json {
        print_json(&report)?;
        return Ok(());
    }

    let accepted_count = report
        .get("accepted")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let rejected_count = report
        .get("rejected")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let skipped_count = report
        .get("skipped")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    println!(
        "Review completed for run {}: accepted={}, rejected={}, skipped={}",
        manifest.run_id, accepted_count, rejected_count, skipped_count
    );

    if rejected_count > 0 {
        println!("Rejected agents:");
        if let Some(items) = report.get("rejected").and_then(Value::as_array) {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let reason = item
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified");
                println!("- {}: {}", name, reason);
            }
        }
    }

    println!("Next: normies integrate --run-id {}", manifest.run_id);
    Ok(())
}

fn cmd_integrate(args: &IntegrateArgs) -> Result<()> {
    let run_id = resolve_run_id(args.run_id.as_deref(), args.latest, true)?;
    let mut manifest = load_manifest_for_run(&run_id)?;
    let review = manifest.review.clone().ok_or_else(|| {
        anyhow!("review report missing; run 'normies review --run-id <id>' first")
    })?;

    let hub_path = PathBuf::from(&manifest.hub_path);
    let run_dir = runs_dir().join(&manifest.run_id);
    let integration_dir = run_dir.join("integration");
    let integration_wt = integration_dir.join("worktree");
    mkdirp(&integration_dir)?;
    let integration_report_path = integration_dir.join("integration.json");
    let codex_handoff_path = integration_dir.join("codex-handoff.md");

    remove_worktree_if_exists(&hub_path, &integration_wt)?;

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

    let accepted_agents: Vec<&AgentState> = manifest
        .agents
        .iter()
        .filter(|a| accepted_set.contains(&a.name))
        .collect();

    let mut blocked = vec![];
    let mut merged = vec![];
    let mut merged_details = vec![];
    let mut integration_head = resolve_ref(&hub_path, &manifest.base_ref).unwrap_or_default();

    if accepted_agents.len() == 1 {
        let agent = accepted_agents[0];
        let worktree = Path::new(&agent.worktree);
        if !worktree.exists() {
            blocked.push(json!({
                "name": agent.name,
                "branch": agent.branch,
                "reason": "agent worktree missing",
                "worktree": agent.worktree,
            }));
        } else {
            let integration_head_before = integration_head.clone();
            let rebase = run_cmd(
                vec![
                    "git".to_string(),
                    "-C".to_string(),
                    worktree.to_string_lossy().to_string(),
                    "rebase".to_string(),
                    manifest.base_ref.clone(),
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
            } else {
                let rebased_agent_head = git_head(worktree).ok();
                let commits = list_commits_in_range(worktree, &manifest.base_ref, &agent.branch);
                let branch_update = git_dir_cmd(
                    &hub_path,
                    &[
                        "branch".to_string(),
                        "-f".to_string(),
                        manifest.integration_branch.clone(),
                        agent.branch.clone(),
                    ],
                    false,
                )?;
                if branch_update.code != 0 {
                    blocked.push(json!({
                        "name": agent.name,
                        "branch": agent.branch,
                        "reason": "failed to move integration branch after rebase",
                        "stderr": branch_update.stderr.trim(),
                        "stdout": branch_update.stdout.trim(),
                        "commits": commits,
                    }));
                } else {
                    integration_head =
                        resolve_ref(&hub_path, &manifest.integration_branch).unwrap_or_default();
                    let commit_count = commits.len();
                    let codex_cherry_pick = if commits.is_empty() {
                        None::<String>
                    } else {
                        Some(format!("git cherry-pick {}", commits.join(" ")))
                    };
                    merged.push(agent.name.clone());
                    merged_details.push(json!({
                        "name": agent.name,
                        "branch": agent.branch,
                        "worktree": agent.worktree,
                        "rebased_agent_head": rebased_agent_head,
                        "integration_head_before": integration_head_before,
                        "integration_head_after": integration_head,
                        "commit_count": commit_count,
                        "commits": commits,
                        "codex_cherry_pick": codex_cherry_pick
                    }));
                }
            }
        }
    } else {
        git_dir_cmd(
            &hub_path,
            &[
                "worktree".to_string(),
                "add".to_string(),
                "-B".to_string(),
                manifest.integration_branch.clone(),
                integration_wt.to_string_lossy().to_string(),
                manifest.base_ref.clone(),
            ],
            true,
        )?;
        integration_head = git_head(&integration_wt).unwrap_or_default();

        for agent in accepted_agents {
            let worktree = Path::new(&agent.worktree);
            if !worktree.exists() {
                blocked.push(json!({
                    "name": agent.name,
                    "branch": agent.branch,
                    "reason": "agent worktree missing",
                    "worktree": agent.worktree,
                }));
                continue;
            }
            let integration_head_before = integration_head.clone();
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

            let rebased_agent_head = git_head(worktree).ok();
            let commits =
                list_commits_in_range(&integration_wt, &integration_head_before, &agent.branch);
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
                    "commits": commits,
                }));
                continue;
            }
            integration_head = git_head(&integration_wt).unwrap_or_default();
            let commit_count = commits.len();
            let codex_cherry_pick = if commits.is_empty() {
                None::<String>
            } else {
                Some(format!("git cherry-pick {}", commits.join(" ")))
            };
            merged.push(agent.name.clone());
            merged_details.push(json!({
                "name": agent.name,
                "branch": agent.branch,
                "worktree": agent.worktree,
                "rebased_agent_head": rebased_agent_head,
                "integration_head_before": integration_head_before,
                "integration_head_after": integration_head,
                "commit_count": commit_count,
                "commits": commits,
                "codex_cherry_pick": codex_cherry_pick
            }));
        }
    }
    let fetch_cmd = format!(
        "git fetch {} {}",
        manifest.hub_path, manifest.integration_branch
    );
    let merge_cmd = "git merge --ff-only FETCH_HEAD".to_string();
    let push_cmd = format!(
        "git --git-dir {} push origin {}",
        manifest.hub_path, manifest.integration_branch
    );
    let inspect_cmd = if integration_wt.exists() {
        format!(
            "git -C {} log --oneline --decorate -n 20",
            integration_wt.to_string_lossy()
        )
    } else {
        format!(
            "git --git-dir {} log --oneline --decorate -n 20 {}",
            manifest.hub_path, manifest.integration_branch
        )
    };
    let handoff = build_codex_handoff_markdown(&CodexHandoffMarkdownArgs {
        manifest: &manifest,
        integration_worktree: &integration_wt,
        integration_report_path: &integration_report_path,
        merged_details: &merged_details,
        blocked: &blocked,
        fetch_cmd: &fetch_cmd,
        merge_cmd: &merge_cmd,
        push_cmd: &push_cmd,
    });
    fs::write(&codex_handoff_path, handoff).with_context(|| {
        format!(
            "failed to write codex handoff markdown: {}",
            codex_handoff_path.display()
        )
    })?;

    let report = json!({
        "run_id": manifest.run_id,
        "created_at": now_iso(),
        "integration_branch": manifest.integration_branch,
        "base_ref": manifest.base_ref,
        "integration_worktree": integration_wt.to_string_lossy().to_string(),
        "integration_head": integration_head,
        "merged": merged,
        "merged_details": merged_details,
        "blocked": blocked,
        "codex": {
            "fetch_integration_branch": fetch_cmd,
            "merge_fetched_branch": merge_cmd,
            "inspect_integration_worktree": inspect_cmd,
            "push_integration_branch": push_cmd,
            "handoff_markdown_path": codex_handoff_path.to_string_lossy().to_string(),
            "integration_report_path": integration_report_path.to_string_lossy().to_string(),
        }
    });
    write_json(&integration_report_path, &report)?;
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

    if args.json {
        print_json(&report)?;
        return Ok(());
    }

    let merged_count = report
        .get("merged")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let blocked_count = report
        .get("blocked")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    println!(
        "Integrate completed for run {}: merged={}, blocked={}",
        manifest.run_id, merged_count, blocked_count
    );
    if blocked_count > 0 {
        println!("Blocked agents:");
        if let Some(items) = report.get("blocked").and_then(Value::as_array) {
            for item in items {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let reason = item
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified");
                println!("- {}: {}", name, reason);
            }
        }
    }
    println!("Codex handoff: {}", codex_handoff_path.to_string_lossy());
    println!(
        "Fetch: {}",
        report
            .get("codex")
            .and_then(|v| v.get("fetch_integration_branch"))
            .and_then(Value::as_str)
            .unwrap_or("-")
    );
    println!(
        "Merge: {}",
        report
            .get("codex")
            .and_then(|v| v.get("merge_fetched_branch"))
            .and_then(Value::as_str)
            .unwrap_or("-")
    );
    println!(
        "Push: {}",
        report
            .get("codex")
            .and_then(|v| v.get("push_integration_branch"))
            .and_then(Value::as_str)
            .unwrap_or("-")
    );
    println!("Next: normies cleanup --run-id {}", manifest.run_id);
    Ok(())
}

fn cmd_cleanup(args: &CleanupArgs) -> Result<()> {
    let run_id = resolve_run_id(args.run_id.as_deref(), args.latest, true)?;
    let manifest = load_manifest_for_run(&run_id)?;
    let hub_path = PathBuf::from(&manifest.hub_path);
    let run_dir = runs_dir().join(&run_id);
    let mut removed_worktrees = vec![];

    let integration_wt = run_dir.join("integration").join("worktree");
    if integration_wt.exists() {
        removed_worktrees.push(integration_wt.to_string_lossy().to_string());
    }
    remove_worktree_if_exists(&hub_path, &integration_wt)?;

    for agent in &manifest.agents {
        let wt = PathBuf::from(&agent.worktree);
        if wt.exists() {
            removed_worktrees.push(wt.to_string_lossy().to_string());
        }
        remove_worktree_if_exists(&hub_path, &wt)?;
    }

    if args.remove_run_dir {
        let _ = fs::remove_dir_all(&run_dir);
    }

    if args.json {
        print_json(&json!({
            "run_id": run_id,
            "removed_worktrees": removed_worktrees,
            "removed_worktree_count": removed_worktrees.len(),
            "removed_run_dir": args.remove_run_dir
        }))?;
        return Ok(());
    }

    println!("Cleanup complete for run {}", run_id);
    println!("Removed worktrees: {}", removed_worktrees.len());
    println!("Removed run directory: {}", args.remove_run_dir);
    Ok(())
}

fn list_commits_in_range(repo_worktree: &Path, from_ref: &str, to_ref: &str) -> Vec<String> {
    if from_ref.trim().is_empty() || to_ref.trim().is_empty() {
        return vec![];
    }
    let range = format!("{from_ref}..{to_ref}");
    let out = run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            repo_worktree.to_string_lossy().to_string(),
            "rev-list".to_string(),
            "--reverse".to_string(),
            range,
        ],
        None,
        false,
        None,
    );
    match out {
        Ok(output) if output.code == 0 => output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => vec![],
    }
}

struct CodexHandoffMarkdownArgs<'a> {
    manifest: &'a RunManifest,
    integration_worktree: &'a Path,
    integration_report_path: &'a Path,
    merged_details: &'a [Value],
    blocked: &'a [Value],
    fetch_cmd: &'a str,
    merge_cmd: &'a str,
    push_cmd: &'a str,
}

fn build_codex_handoff_markdown(args: &CodexHandoffMarkdownArgs<'_>) -> String {
    let mut md = String::new();
    md.push_str("# Codex merge handoff\n\n");
    md.push_str(&format!("- Run id: `{}`\n", args.manifest.run_id));
    md.push_str(&format!(
        "- Integration branch: `{}`\n",
        args.manifest.integration_branch
    ));
    md.push_str(&format!(
        "- Integration worktree: `{}`\n",
        args.integration_worktree.to_string_lossy()
    ));
    md.push_str(&format!(
        "- Integration report: `{}`\n\n",
        args.integration_report_path.to_string_lossy()
    ));
    md.push_str("## Codex-friendly merge commands\n\n");
    md.push_str("```bash\n");
    md.push_str(args.fetch_cmd);
    md.push('\n');
    md.push_str(args.merge_cmd);
    md.push('\n');
    md.push_str(args.push_cmd);
    md.push_str("\n```\n\n");

    md.push_str("## Merged agents\n\n");
    if args.merged_details.is_empty() {
        md.push_str("None.\n\n");
    } else {
        for detail in args.merged_details {
            let name = detail
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let branch = detail
                .get("branch")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            md.push_str(&format!("- `{name}` (`{branch}`)\n"));
            if let Some(commits) = detail.get("commits").and_then(Value::as_array)
                && !commits.is_empty()
            {
                let joined = commits
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                if !joined.is_empty() {
                    md.push_str(&format!("  - cherry-pick: `git cherry-pick {joined}`\n"));
                }
            }
        }
        md.push('\n');
    }

    md.push_str("## Blocked agents\n\n");
    if args.blocked.is_empty() {
        md.push_str("None.\n");
    } else {
        for item in args.blocked {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let reason = item
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unspecified");
            md.push_str(&format!("- `{name}`: {reason}\n"));
        }
    }
    md
}

#[derive(Debug)]
struct DoctorCheck {
    name: String,
    ok: bool,
    detail: String,
    fix: String,
}

fn cmd_doctor(args: &DoctorArgs) -> Result<()> {
    let mut checks = vec![];

    checks.push(match check_tool_exists("git") {
        Ok(()) => DoctorCheck {
            name: "git".to_string(),
            ok: true,
            detail: "found in PATH".to_string(),
            fix: "".to_string(),
        },
        Err(err) => DoctorCheck {
            name: "git".to_string(),
            ok: false,
            detail: err.to_string(),
            fix: "Install git and ensure it is on PATH.".to_string(),
        },
    });

    checks.push(match check_tool_exists("docker") {
        Ok(()) => DoctorCheck {
            name: "docker".to_string(),
            ok: true,
            detail: "found in PATH".to_string(),
            fix: "".to_string(),
        },
        Err(err) => DoctorCheck {
            name: "docker".to_string(),
            ok: false,
            detail: err.to_string(),
            fix: "Install Docker Desktop/Engine and ensure docker is on PATH.".to_string(),
        },
    });

    checks.push(match ensure_docker_daemon() {
        Ok(()) => DoctorCheck {
            name: "docker-daemon".to_string(),
            ok: true,
            detail: if fake_docker_mode() {
                "fake docker mode enabled".to_string()
            } else {
                "docker daemon reachable".to_string()
            },
            fix: "".to_string(),
        },
        Err(err) => DoctorCheck {
            name: "docker-daemon".to_string(),
            ok: false,
            detail: err.to_string(),
            fix: "Start Docker daemon before running normies.".to_string(),
        },
    });

    let repo_target = args.repo.clone().unwrap_or_else(|| ".".to_string());
    checks.push(match check_repo_access(&repo_target) {
        Ok(detail) => DoctorCheck {
            name: "repo".to_string(),
            ok: true,
            detail,
            fix: "".to_string(),
        },
        Err(err) => DoctorCheck {
            name: "repo".to_string(),
            ok: false,
            detail: err.to_string(),
            fix: "Use a local git repo path or a reachable remote URL/owner/repo slug.".to_string(),
        },
    });

    checks.push(match check_orchestrator_writable() {
        Ok(detail) => DoctorCheck {
            name: "orchestrator-dir".to_string(),
            ok: true,
            detail,
            fix: "".to_string(),
        },
        Err(err) => DoctorCheck {
            name: "orchestrator-dir".to_string(),
            ok: false,
            detail: err.to_string(),
            fix: "Ensure .orchestrator path is writable.".to_string(),
        },
    });

    let failed: Vec<&DoctorCheck> = checks.iter().filter(|c| !c.ok).collect();

    if args.json {
        let payload = json!({
            "ok": failed.is_empty(),
            "checks": checks
                .iter()
                .map(|c| json!({
                    "name": c.name,
                    "ok": c.ok,
                    "detail": c.detail,
                    "fix": c.fix,
                }))
                .collect::<Vec<_>>()
        });
        print_json(&payload)?;
    } else {
        println!("Normies doctor");
        for check in &checks {
            println!(
                "- {:<18} {:<4} {}",
                check.name,
                if check.ok { "ok" } else { "fail" },
                check.detail
            );
            if !check.ok {
                println!("  fix: {}", check.fix);
            }
        }
    }

    if !failed.is_empty() {
        bail!("doctor found {} failing check(s)", failed.len());
    }
    Ok(())
}

fn check_repo_access(repo_target: &str) -> Result<String> {
    let path = Path::new(repo_target);
    if path.exists() {
        run_cmd(
            vec![
                "git".to_string(),
                "-C".to_string(),
                path.to_string_lossy().to_string(),
                "rev-parse".to_string(),
                "--is-inside-work-tree".to_string(),
            ],
            None,
            true,
            None,
        )?;
        return Ok(format!("local repository is readable: {}", path.display()));
    }

    let normalized = normalize_repo_input(repo_target)?;
    run_cmd(
        vec![
            "git".to_string(),
            "ls-remote".to_string(),
            normalized.clone(),
            "HEAD".to_string(),
        ],
        None,
        true,
        None,
    )?;
    Ok(format!("remote repository is reachable: {normalized}"))
}

fn check_orchestrator_writable() -> Result<String> {
    ensure_orch_dirs()?;
    let probe = orch_dir().join(".doctor-write-test");
    fs::write(&probe, "ok")
        .with_context(|| format!("cannot write probe file in {}", orch_dir().display()))?;
    fs::remove_file(&probe).ok();
    Ok(format!("writable: {}", orch_dir().display()))
}

const INIT_BLOCK_START: &str = "<!-- normies:init:start -->";
const INIT_BLOCK_END: &str = "<!-- normies:init:end -->";

const CLAUDE_NORMIES_SKILL: &str = r#"---
name: normies-workflow
description: Orchestrate Docker-isolated, branch-based multi-agent git workflows with normies. Use for parallel edits, retries, and explicit review/integration gates.
---

<!-- normies:init:start -->
# Normies Workflow

## When To Use

Use this skill when work should be parallelized across multiple agents or needs branch-isolated execution with review gates.

## Run Sequence

1. `normies doctor --repo <repo>`
2. `normies init --template baseline --output normies.spec.json --repo <repo> --yes`
3. `normies run --repo <repo> --spec normies.spec.json --jobs <N>`
4. `normies retry --run-id <run_id> --failed --jobs <N>` (if needed)
5. `normies review --run-id <run_id>`
6. `normies integrate --run-id <run_id>`
7. `normies cleanup --run-id <run_id>`

## Default Guardrails

- Keep `needs_network` disabled unless required.
- Keep commands idempotent and non-interactive.
- Keep `review.required_checks` explicit.
<!-- normies:init:end -->
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AgentContextTarget {
    Codex,
    Claude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteAction {
    Created,
    Updated,
    Unchanged,
    Skipped,
}

impl WriteAction {
    fn label(self) -> &'static str {
        match self {
            WriteAction::Created => "created",
            WriteAction::Updated => "updated",
            WriteAction::Unchanged => "unchanged",
            WriteAction::Skipped => "skipped",
        }
    }
}

fn parse_agent_context_targets(raw_values: &[String]) -> Result<HashSet<AgentContextTarget>> {
    let mut targets = HashSet::new();
    for raw in raw_values {
        for part in raw.split(',') {
            let token = part.trim().to_lowercase();
            if token.is_empty() {
                continue;
            }
            match token.as_str() {
                "codex" => {
                    targets.insert(AgentContextTarget::Codex);
                }
                "claude" => {
                    targets.insert(AgentContextTarget::Claude);
                }
                "all" => {
                    targets.insert(AgentContextTarget::Codex);
                    targets.insert(AgentContextTarget::Claude);
                }
                _ => {
                    bail!(
                        "unknown --agent-context value '{token}'. expected one of: codex, claude, all"
                    );
                }
            }
        }
    }
    Ok(targets)
}

fn resolve_agent_guidance_root(repo: Option<&str>) -> Result<PathBuf> {
    if let Some(repo_value) = repo {
        let repo_path = Path::new(repo_value);
        if repo_path.exists() {
            return Ok(repo_path
                .canonicalize()
                .unwrap_or_else(|_| repo_path.to_path_buf()));
        }
    }
    std::env::current_dir().context("failed to resolve current directory for agent guidance")
}

fn build_agents_guidance_block() -> String {
    format!(
        "{INIT_BLOCK_START}\n## Normies-First Rule\n\nUse `normies` by default when tasks involve parallel work, multiple independent edits, retries, or explicit review/integration gates.\n\n### Trigger Phrases\n\n- multi-agent\n- parallel changes\n- batch fixes\n- orchestrate\n- branch-isolated\n- retry failed agents\n\n### Default Sequence\n\n1. `normies doctor --repo <repo>`\n2. `normies init --template baseline --output normies.spec.json --repo <repo> --agent-context codex,claude --yes`\n3. `normies run --repo <repo> --spec normies.spec.json --jobs <N>`\n4. `normies retry --run-id <run_id> --failed --jobs <N>` (if needed)\n5. `normies review --run-id <run_id>`\n6. `normies integrate --run-id <run_id>`\n7. `normies cleanup --run-id <run_id>`\n\nSkip normies only for trivial one-file edits that do not need orchestration.\n{INIT_BLOCK_END}"
    )
}

fn upsert_marked_block(existing: &str, block: &str) -> String {
    if let Some(start_idx) = existing.find(INIT_BLOCK_START)
        && let Some(end_rel) = existing[start_idx..].find(INIT_BLOCK_END)
    {
        let end_idx = start_idx + end_rel + INIT_BLOCK_END.len();
        let before = existing[..start_idx].trim_end_matches('\n');
        let after = existing[end_idx..].trim_start_matches('\n');

        let mut out = String::new();
        if !before.is_empty() {
            out.push_str(before);
            out.push_str("\n\n");
        }
        out.push_str(block.trim_end());
        if !after.trim().is_empty() {
            out.push_str("\n\n");
            out.push_str(after.trim_end());
        }
        out.push('\n');
        return out;
    }

    let mut out = existing.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(block.trim_end());
    out.push('\n');
    out
}

fn write_or_update_file(
    path: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
    allow_append: bool,
) -> Result<WriteAction> {
    let existing = match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("failed reading {}", path.display()));
        }
    };

    let desired = if let Some(text) = existing.as_deref() {
        if allow_append {
            upsert_marked_block(text, content)
        } else {
            content.to_string()
        }
    } else if allow_append {
        format!("# Agent Instructions\n\n{}\n", content.trim_end())
    } else {
        content.to_string()
    };

    if let Some(current) = existing.as_deref() {
        if current == desired {
            return Ok(WriteAction::Unchanged);
        }
        if !allow_append
            && !force
            && !(current.contains(INIT_BLOCK_START) && current.contains(INIT_BLOCK_END))
        {
            return Ok(WriteAction::Skipped);
        }
    }

    if !dry_run {
        if let Some(parent) = path.parent() {
            mkdirp(parent)?;
        }
        fs::write(path, desired).with_context(|| format!("failed writing {}", path.display()))?;
    }

    Ok(if existing.is_some() {
        WriteAction::Updated
    } else {
        WriteAction::Created
    })
}

fn scaffold_agent_guidance(
    root: &Path,
    targets: &HashSet<AgentContextTarget>,
    force: bool,
    dry_run: bool,
) -> Result<Vec<String>> {
    let mut notes = vec![];

    if targets.contains(&AgentContextTarget::Codex) {
        let path = root.join("AGENTS.md");
        let action =
            write_or_update_file(&path, &build_agents_guidance_block(), true, dry_run, true)?;
        notes.push(format!("{} ({})", path.display(), action.label()));
    }

    if targets.contains(&AgentContextTarget::Claude) {
        let path = root.join(".claude/skills/normies-workflow/SKILL.md");
        let action = write_or_update_file(&path, CLAUDE_NORMIES_SKILL, force, dry_run, false)?;
        notes.push(format!("{} ({})", path.display(), action.label()));
    }

    Ok(notes)
}

fn cmd_init(args: &InitArgs) -> Result<()> {
    let mut template = normalize_template(&args.template)?;
    let mut repo = args.repo.clone();
    let mut base_ref = DEFAULT_BASE_REF.to_string();
    let mut image = DEFAULT_IMAGE.to_string();
    let mut auto_commit = true;
    let mut agent_entries: Vec<(String, String)> = vec![];
    let agent_context_targets = parse_agent_context_targets(&args.agent_context)?;

    if args.yes {
        agent_entries.push((
            "agent-1".to_string(),
            "echo \"hello from normies\" > AGENT_OUTPUT.txt".to_string(),
        ));
    } else {
        println!("Normies init wizard");
        println!("Press Enter to accept defaults.");

        let selected = prompt_with_default(
            "Template (minimal|baseline)",
            if template == "minimal" {
                "minimal"
            } else {
                "baseline"
            },
        )?;
        template = normalize_template(&selected)?;

        if repo.is_none() {
            let repo_in = prompt_with_default("Repo (owner/repo, URL, or local path)", "")?;
            if !repo_in.trim().is_empty() {
                repo = Some(repo_in.trim().to_string());
            }
        }

        base_ref = prompt_with_default("Base ref", DEFAULT_BASE_REF)?;
        image = prompt_with_default("Container image", DEFAULT_IMAGE)?;

        loop {
            let raw = prompt_with_default("Agent (name::command)", "")?;
            if raw.trim().is_empty() {
                if agent_entries.is_empty() {
                    println!("At least one agent is required.");
                    continue;
                }
                break;
            }
            let (name, cmd) = parse_agent_entry(&raw)?;
            agent_entries.push((name, cmd));

            if !prompt_yes_no("Add another agent?", false)? {
                break;
            }
        }

        auto_commit = prompt_yes_no("Auto-commit agent changes?", true)?;
    }

    let agents = agent_entries
        .into_iter()
        .map(|(name, cmd)| AgentSpec {
            name,
            cmd,
            base_ref: None,
            image: None,
            env: HashMap::new(),
            cpus: None,
            memory: None,
            pids_limit: None,
            needs_network: None,
            read_only_rootfs: None,
            auto_commit: None,
            commit_prefix: None,
            commit_message: None,
            required_checks: vec![],
            a2a: None,
        })
        .collect::<Vec<_>>();

    let mut spec = Spec {
        schema_version: Some(crate::models::CURRENT_SPEC_VERSION),
        repo,
        base_ref: Some(base_ref),
        image: Some(image),
        defaults: None,
        review: None,
        a2a_gateway: None,
        agents,
    };

    if template == "baseline" {
        spec.defaults = Some(SpecDefaults {
            cpus: Some(DEFAULT_CPUS.to_string()),
            memory: Some(DEFAULT_MEMORY.to_string()),
            pids_limit: Some(DEFAULT_PIDS_LIMIT),
            needs_network: Some(false),
            auto_commit: Some(auto_commit),
            read_only_rootfs: Some(false),
            commit_prefix: Some("agent".to_string()),
        });
        spec.review = Some(ReviewConfig {
            required_checks: vec!["git diff --check".to_string()],
        });
    }

    validate_spec(&spec)?;

    if let Some(parent) = args.output.parent() {
        if !args.dry_run {
            mkdirp(parent)?;
        }
    }
    if !args.dry_run {
        write_json(&args.output, &serde_json::to_value(&spec)?)?;
    }

    if args.dry_run {
        println!(
            "Dry-run: would write {} template spec to {}",
            template,
            args.output.display()
        );
    } else {
        println!(
            "Wrote {} template spec to {}",
            template,
            args.output
                .canonicalize()
                .unwrap_or(args.output.clone())
                .display()
        );
    }
    if !agent_context_targets.is_empty() {
        let guidance_root = resolve_agent_guidance_root(spec.repo.as_deref())?;
        let writes = scaffold_agent_guidance(
            &guidance_root,
            &agent_context_targets,
            args.force,
            args.dry_run,
        )?;
        println!("Agent guidance root: {}", guidance_root.display());
        for entry in writes {
            println!("- {}", entry);
        }
    }
    if args.dry_run {
        println!("Next: rerun without --dry-run to write files.");
    } else if spec.repo.is_some() {
        println!(
            "Next: normies run --spec {}",
            args.output
                .canonicalize()
                .unwrap_or(args.output.clone())
                .display()
        );
    } else {
        println!(
            "Next: normies run --repo <repo> --spec {}",
            args.output
                .canonicalize()
                .unwrap_or(args.output.clone())
                .display()
        );
    }
    Ok(())
}

fn normalize_template(template: &str) -> Result<String> {
    let trimmed = template.trim().to_lowercase();
    match trimmed.as_str() {
        "minimal" | "baseline" => Ok(trimmed),
        _ => bail!("unknown template '{template}'. use 'minimal' or 'baseline'"),
    }
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", prompt, default);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let marker = if default_yes { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", prompt, marker);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let value = input.trim().to_lowercase();
    if value.is_empty() {
        return Ok(default_yes);
    }
    if value == "y" || value == "yes" {
        return Ok(true);
    }
    if value == "n" || value == "no" {
        return Ok(false);
    }
    bail!("please answer yes or no")
}

fn cmd_make_spec(args: &MakeSpecArgs) -> Result<()> {
    if args.agents.is_empty() {
        bail!("at least one --agent is required");
    }
    if args.auto_commit && args.no_auto_commit {
        bail!("--auto-commit and --no-auto-commit cannot be used together");
    }

    let network_set: HashSet<String> = args.network_agents.iter().cloned().collect();
    let mut seen = HashSet::new();
    let mut agents = vec![];
    for raw in &args.agents {
        let (name, cmd) = parse_agent_entry(raw)?;
        if !seen.insert(name.clone()) {
            bail!("duplicate --agent name: {name}");
        }
        agents.push(AgentSpec {
            name,
            cmd,
            base_ref: None,
            image: None,
            env: HashMap::new(),
            cpus: None,
            memory: None,
            pids_limit: None,
            needs_network: None,
            read_only_rootfs: None,
            auto_commit: None,
            commit_prefix: None,
            commit_message: None,
            required_checks: vec![],
            a2a: None,
        });
    }

    for network_agent in &network_set {
        if !seen.contains(network_agent) {
            bail!("--network-agent references unknown agent: {network_agent}");
        }
    }

    for agent in &mut agents {
        if network_set.contains(&agent.name) {
            agent.needs_network = Some(true);
        }
    }

    let auto_commit = !args.no_auto_commit;
    let spec = Spec {
        schema_version: Some(crate::models::CURRENT_SPEC_VERSION),
        repo: args.repo.clone(),
        base_ref: Some(args.base_ref.clone()),
        image: Some(args.image.clone()),
        defaults: Some(SpecDefaults {
            cpus: Some(args.cpus.clone()),
            memory: Some(args.memory.clone()),
            pids_limit: Some(args.pids_limit),
            needs_network: Some(false),
            auto_commit: Some(auto_commit),
            read_only_rootfs: Some(false),
            commit_prefix: Some("agent".to_string()),
        }),
        review: Some(ReviewConfig {
            required_checks: args.checks.clone(),
        }),
        a2a_gateway: None,
        agents,
    };
    validate_spec(&spec)?;

    if let Some(parent) = args.output.parent() {
        mkdirp(parent)?;
    }
    write_json(&args.output, &serde_json::to_value(&spec)?)?;
    println!(
        "{}",
        args.output
            .canonicalize()
            .unwrap_or(args.output.clone())
            .display()
    );
    Ok(())
}

fn resolve_run_id(run_id: Option<&str>, latest: bool, default_latest: bool) -> Result<String> {
    if run_id.is_some() && latest {
        bail!("use either --run-id or --latest, not both");
    }
    if let Some(run_id) = run_id {
        return Ok(run_id.to_string());
    }
    if latest || default_latest {
        return latest_run_id();
    }
    bail!("run id is required; use --run-id <id> or --latest")
}

fn latest_run_id() -> Result<String> {
    let runs = list_runs()?;
    runs.last().cloned().ok_or_else(|| {
        anyhow!("no runs found. start one with: normies run --repo <repo> --spec <spec>")
    })
}

fn resolve_ref_once(
    hub_path: &Path,
    reference: &str,
    resolved_refs: &mut HashSet<String>,
) -> Result<()> {
    if resolved_refs.insert(reference.to_string()) {
        resolve_ref(hub_path, reference)?;
    }
    Ok(())
}

fn load_manifest_for_run(run_id: &str) -> Result<RunManifest> {
    match repo_from_manifest(run_id) {
        Ok(manifest) => Ok(manifest),
        Err(_) => {
            let runs = list_runs().unwrap_or_default();
            if runs.is_empty() {
                bail!(
                    "run not found: {}. no runs exist yet. start one with: normies run --repo <repo> --spec <spec>",
                    run_id
                );
            }
            let mut latest = runs;
            latest.sort();
            let recent = latest
                .into_iter()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "run not found: {}. available recent runs: {}. use: normies status",
                run_id,
                recent
            )
        }
    }
}

fn print_agent_summary(agents: &[AgentState]) {
    if agents.is_empty() {
        println!("No agents.");
        return;
    }
    println!("Agents:");
    for agent in agents {
        println!(
            "- {:<24} {:<12} exit={:<3} committed={} branch={}",
            agent.name, agent.status, agent.exit_code, agent.committed, agent.branch
        );
    }
}

const A2A_GATEWAY_SOCKET_MOUNT: &str = "/gateway/gateway.sock";
const A2A_GATEWAY_BASE_URL: &str = "http://a2a.local";

struct GatewayRunContext {
    config: A2aGatewayConfig,
    gateway_dir: PathBuf,
    gateway_socket_host: PathBuf,
    gateway_log_path: PathBuf,
    token_by_agent: HashMap<String, String>,
    peers_json_by_agent: HashMap<String, String>,
    start_agents: Vec<GatewayStartAgent>,
}

struct GatewayPrepareContext<'a> {
    gateway_dir: &'a Path,
    token_by_agent: &'a HashMap<String, String>,
    peers_json_by_agent: &'a HashMap<String, String>,
}

fn random_bearer_token() -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(48);
    for _ in 0..48 {
        out.push_str(&format!("{:x}", rng.random_range(0..16)));
    }
    out
}

fn prepare_gateway_context(
    spec: &Spec,
    selected_agents: &[&AgentSpec],
    run_dir: &Path,
) -> Result<Option<GatewayRunContext>> {
    let Some(config) = spec.a2a_gateway.clone() else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    if selected_agents.is_empty() {
        return Ok(None);
    }

    let gateway_dir = run_dir.join("gateway");
    let agents_dir = gateway_dir.join("agents");
    mkdirp(&agents_dir)?;
    let gateway_socket_host = gateway_dir.join("gateway.sock");
    let gateway_log_path = gateway_dir.join("gateway.log");

    let mut token_by_agent = HashMap::new();
    for agent in selected_agents {
        token_by_agent.insert(agent.name.clone(), random_bearer_token());
    }

    let mut start_agents = vec![];
    for agent in selected_agents {
        let a2a = agent.a2a.clone().unwrap_or_default();
        start_agents.push(GatewayStartAgent {
            name: agent.name.clone(),
            serve: a2a.serve,
            description: a2a.description,
            skills: a2a.skills,
            streaming: a2a.streaming.unwrap_or(false),
            socket_path: agents_dir.join(format!("{}.sock", agent.name)),
        });
    }

    let mut peers_json_by_agent = HashMap::new();
    for agent in selected_agents {
        let peers = start_agents
            .iter()
            .filter(|peer| peer.serve)
            .map(|peer| {
                (
                    peer.name.clone(),
                    json!({
                        "base_url": format!("{A2A_GATEWAY_BASE_URL}/v1/agents/{}", peer.name),
                        "card_url": format!("{A2A_GATEWAY_BASE_URL}/v1/agents/{}/.well-known/agent-card.json", peer.name),
                        "streaming": peer.streaming,
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        peers_json_by_agent.insert(agent.name.clone(), Value::Object(peers).to_string());
    }

    let token_path = gateway_dir.join("tokens.json");
    let token_value = Value::Object(
        token_by_agent
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect(),
    );
    write_json(&token_path, &token_value)?;

    Ok(Some(GatewayRunContext {
        config,
        gateway_dir,
        gateway_socket_host,
        gateway_log_path,
        token_by_agent,
        peers_json_by_agent,
        start_agents,
    }))
}

fn stop_gateway(
    gateway_handle: Option<&mut GatewayHandle>,
    fallback: Option<&GatewayTelemetry>,
) -> Result<Option<GatewayTelemetry>> {
    let Some(handle) = gateway_handle else {
        return Ok(fallback.cloned());
    };
    let telemetry = handle.stop()?;
    Ok(Some(telemetry))
}

struct PrepareContext<'a> {
    run_id: &'a str,
    run_dir: &'a Path,
    hub_path: &'a Path,
    base_ref: &'a str,
    defaults: &'a SpecDefaults,
    global_image: &'a str,
    gateway: Option<GatewayPrepareContext<'a>>,
}

fn prepare_agent(
    ctx: &PrepareContext<'_>,
    agent: &AgentSpec,
    branch_override: Option<&str>,
) -> Result<PreparedAgent> {
    let agent_dir = ctx.run_dir.join("agents").join(&agent.name);
    let worktree = agent_dir.join("worktree");
    let out_dir = agent_dir.join("out");
    let log_path = agent_dir.join("docker.log");
    mkdirp(&out_dir)?;

    let agent_base_ref = agent
        .base_ref
        .clone()
        .unwrap_or_else(|| ctx.base_ref.to_string());

    let branch = branch_override
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("agent/{}/{}", ctx.run_id, agent.name));
    let before_head =
        ensure_agent_branch_worktree(ctx.hub_path, &agent_base_ref, &branch, &worktree)?;

    let image = agent
        .image
        .clone()
        .unwrap_or_else(|| ctx.global_image.to_string());
    let cpus = agent
        .cpus
        .clone()
        .or(ctx.defaults.cpus.clone())
        .unwrap_or_else(|| DEFAULT_CPUS.to_string());
    let memory = agent
        .memory
        .clone()
        .or(ctx.defaults.memory.clone())
        .unwrap_or_else(|| DEFAULT_MEMORY.to_string());
    let pids_limit = agent
        .pids_limit
        .or(ctx.defaults.pids_limit)
        .unwrap_or(DEFAULT_PIDS_LIMIT);
    let needs_network = agent
        .needs_network
        .or(ctx.defaults.needs_network)
        .unwrap_or(false);
    let read_only_rootfs = agent
        .read_only_rootfs
        .or(ctx.defaults.read_only_rootfs)
        .unwrap_or(false);
    let auto_commit = agent
        .auto_commit
        .or(ctx.defaults.auto_commit)
        .unwrap_or(true);
    let commit_prefix = agent
        .commit_prefix
        .clone()
        .or(ctx.defaults.commit_prefix.clone())
        .unwrap_or_else(|| "agent".to_string());

    let mut env_map = HashMap::new();
    env_map.insert("AGENT_NAME".to_string(), agent.name.clone());
    env_map.insert("RUN_ID".to_string(), ctx.run_id.to_string());
    env_map.insert("AGENT_BRANCH".to_string(), branch.clone());
    env_map.insert("AGENT_BASE_REF".to_string(), agent_base_ref.clone());
    let mut gateway_dir = None;
    if let Some(gateway) = &ctx.gateway {
        let token = gateway
            .token_by_agent
            .get(&agent.name)
            .ok_or_else(|| anyhow!("missing A2A token for agent {}", agent.name))?;
        let peers_json = gateway
            .peers_json_by_agent
            .get(&agent.name)
            .ok_or_else(|| anyhow!("missing A2A peers payload for agent {}", agent.name))?;

        env_map.insert(
            "NORMIES_A2A_GATEWAY_SOCKET".to_string(),
            A2A_GATEWAY_SOCKET_MOUNT.to_string(),
        );
        env_map.insert(
            "NORMIES_A2A_GATEWAY_BASE_URL".to_string(),
            A2A_GATEWAY_BASE_URL.to_string(),
        );
        env_map.insert("NORMIES_A2A_AGENT_ID".to_string(), agent.name.clone());
        env_map.insert(
            "NORMIES_A2A_AGENT_SOCKET".to_string(),
            format!("/gateway/agents/{}.sock", agent.name),
        );
        env_map.insert("NORMIES_A2A_TOKEN".to_string(), token.clone());
        env_map.insert("NORMIES_A2A_PEERS_JSON".to_string(), peers_json.clone());
        gateway_dir = Some(gateway.gateway_dir.to_path_buf());
    }
    for (k, v) in &agent.env {
        env_map.insert(k.clone(), v.clone());
    }

    let container_name = format!(
        "agent-{}-{}",
        ctx.run_id,
        sanitize_container_name(&agent.name)
    );

    Ok(PreparedAgent {
        name: agent.name.clone(),
        branch,
        base_ref: agent_base_ref,
        before_head,
        worktree,
        out_dir,
        log_path,
        image,
        cmd: agent.cmd.clone(),
        needs_network,
        read_only_rootfs,
        required_checks: agent.required_checks.clone(),
        auto_commit,
        commit_prefix,
        commit_message: agent.commit_message.clone(),
        cpus,
        memory,
        pids_limit,
        container_name,
        env_map,
        gateway_dir,
    })
}

#[derive(Debug)]
enum AgentExecutionOutcome {
    Ok(Box<AgentState>),
    Err(String),
}

fn execute_prepared_agents(
    prepared: Vec<PreparedAgent>,
    jobs: usize,
    progress: bool,
) -> Result<Vec<AgentState>> {
    if prepared.is_empty() {
        return Ok(vec![]);
    }

    if progress {
        for agent in &prepared {
            println!("[queued] {}", agent.name);
        }
    }

    if jobs <= 1 || prepared.len() == 1 {
        let mut out = Vec::with_capacity(prepared.len());
        for agent in prepared {
            if progress {
                println!("[running] {}", agent.name);
            }
            let start = Instant::now();
            let state = execute_agent(agent)?;
            if progress {
                println!(
                    "[{}] {} ({:.1}s)",
                    state.status,
                    state.name,
                    start.elapsed().as_secs_f64()
                );
            }
            out.push(state);
        }
        return Ok(out);
    }

    let total = prepared.len();
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut guard = queue.lock().expect("queue lock poisoned");
        for (idx, agent) in prepared.into_iter().enumerate() {
            guard.push_back((idx, agent));
        }
    }

    let results: Arc<Mutex<Vec<Option<AgentExecutionOutcome>>>> =
        Arc::new(Mutex::new((0..total).map(|_| None).collect()));
    let log_lock = Arc::new(Mutex::new(()));

    let worker_count = jobs.min(total);
    let mut handles = vec![];
    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        let log_lock = Arc::clone(&log_lock);
        handles.push(thread::spawn(move || {
            loop {
                let next = {
                    let mut guard = queue.lock().expect("queue lock poisoned");
                    guard.pop_front()
                };
                let Some((idx, agent)) = next else {
                    break;
                };

                if progress {
                    let _guard = log_lock.lock().expect("log lock poisoned");
                    println!("[running] {}", agent.name);
                }

                let started = Instant::now();
                let outcome = match execute_agent(agent) {
                    Ok(state) => {
                        if progress {
                            let _guard = log_lock.lock().expect("log lock poisoned");
                            println!(
                                "[{}] {} ({:.1}s)",
                                state.status,
                                state.name,
                                started.elapsed().as_secs_f64()
                            );
                        }
                        AgentExecutionOutcome::Ok(Box::new(state))
                    }
                    Err(err) => {
                        if progress {
                            let _guard = log_lock.lock().expect("log lock poisoned");
                            println!("[error] {} ({:.1}s)", err, started.elapsed().as_secs_f64());
                        }
                        AgentExecutionOutcome::Err(err.to_string())
                    }
                };

                let mut guard = results.lock().expect("results lock poisoned");
                guard[idx] = Some(outcome);
            }
        }));
    }

    for handle in handles {
        if handle.join().is_err() {
            bail!("agent worker thread panicked");
        }
    }

    let mut guard = results.lock().expect("results lock poisoned");
    let mut ordered = Vec::with_capacity(total);
    for (idx, item) in guard.iter_mut().enumerate() {
        let Some(outcome) = item.take() else {
            bail!("internal error: missing result for agent index {idx}");
        };
        match outcome {
            AgentExecutionOutcome::Ok(state) => ordered.push(*state),
            AgentExecutionOutcome::Err(err) => {
                bail!("agent execution failed at index {idx}: {err}");
            }
        }
    }

    Ok(ordered)
}

fn execute_agent(agent: PreparedAgent) -> Result<AgentState> {
    if agent.out_dir.exists() {
        fs::remove_dir_all(&agent.out_dir)
            .with_context(|| format!("failed to reset {}", agent.out_dir.display()))?;
    }
    mkdirp(&agent.out_dir)?;

    let docker_cmd = docker_command(DockerCmdOptions {
        container_name: agent.container_name.clone(),
        image: agent.image.clone(),
        cmd: agent.cmd.clone(),
        worktree: agent.worktree.clone(),
        out_dir: agent.out_dir.clone(),
        env_map: agent.env_map.clone(),
        cpus: agent.cpus.clone(),
        memory: agent.memory.clone(),
        pids_limit: agent.pids_limit,
        needs_network: agent.needs_network,
        read_only_rootfs: agent.read_only_rootfs,
        gateway_dir: agent.gateway_dir.clone(),
    })?;

    let exit_code = run_logged(&docker_cmd, &agent.log_path, None)?;

    let commit_info = ensure_commit_if_needed(
        &agent.worktree,
        &agent.before_head,
        &agent.name,
        &agent.commit_prefix,
        agent.commit_message.as_deref(),
        agent.auto_commit,
    )?;

    let existing_result = read_result_json(&agent.out_dir)?;
    let result_obj = normalized_result(
        &agent.name,
        exit_code,
        commit_info.committed,
        commit_info.dirty_uncommitted,
        existing_result,
    );
    write_json(&agent.out_dir.join("result.json"), &result_obj)?;

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

    Ok(AgentState {
        name: agent.name,
        branch: agent.branch,
        base_ref: agent.base_ref,
        before_head: agent.before_head,
        after_head: commit_info.after_head,
        committed: commit_info.committed,
        auto_committed: commit_info.auto_committed,
        dirty_uncommitted: commit_info.dirty_uncommitted,
        exit_code,
        status,
        summary,
        worktree: agent.worktree.to_string_lossy().to_string(),
        out_dir: agent.out_dir.to_string_lossy().to_string(),
        log_path: agent.log_path.to_string_lossy().to_string(),
        image: agent.image,
        cmd: agent.cmd,
        needs_network: agent.needs_network,
        read_only_rootfs: agent.read_only_rootfs,
        required_checks: agent.required_checks,
    })
}
