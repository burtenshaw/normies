use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use rand::Rng;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::models::{CURRENT_SPEC_VERSION, CmdOutput, CommitInfo, RunManifest, Spec};

pub const ORCH_DIR_ENV: &str = "NORMIES_ORCH_DIR";
pub const FAKE_DOCKER_ENV: &str = "NORMIES_TEST_FAKE_DOCKER";
static UID_GID_CACHE: OnceLock<(String, String)> = OnceLock::new();

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn orch_dir() -> PathBuf {
    std::env::var(ORCH_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".orchestrator"))
}

pub fn runs_dir() -> PathBuf {
    orch_dir().join("runs")
}

pub fn repos_dir() -> PathBuf {
    orch_dir().join("repos")
}

pub fn fake_docker_mode() -> bool {
    std::env::var(FAKE_DOCKER_ENV).ok().as_deref() == Some("1")
}

pub fn run_cmd(
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
    Ok(CmdOutput {
        code,
        stdout,
        stderr,
    })
}

fn run_command_to_existing_log(
    cmd: &[String],
    cwd: Option<&Path>,
    env_map: Option<&HashMap<String, String>>,
    log: &fs::File,
) -> Result<i32> {
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
    command.stdout(Stdio::from(log.try_clone()?));
    command.stderr(Stdio::from(log.try_clone()?));

    let status = command
        .status()
        .with_context(|| format!("failed to run command: {}", cmd.join(" ")))?;
    Ok(status.code().unwrap_or(1))
}

fn run_command_to_log(
    cmd: &[String],
    logfile: &Path,
    cwd: Option<&Path>,
    env_map: Option<&HashMap<String, String>>,
) -> Result<i32> {
    if let Some(parent) = logfile.parent() {
        mkdirp(parent)?;
    }
    let mut file = fs::File::create(logfile)?;
    writeln!(file, "$ {}", cmd.join(" "))?;
    let code = run_command_to_existing_log(cmd, cwd, env_map, &file)?;
    writeln!(file, "\n[exit_code={code}]")?;
    Ok(code)
}

pub fn run_logged(cmd: &[String], logfile: &Path, cwd: Option<&Path>) -> Result<i32> {
    if fake_docker_mode() && cmd.first().map(String::as_str) == Some("docker") {
        return run_fake_docker(cmd, logfile);
    }
    run_command_to_log(cmd, logfile, cwd, None)
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
        if cmd[i] == "-e"
            && i + 1 < cmd.len()
            && let Some((k, v)) = cmd[i + 1].split_once('=')
        {
            env_map.insert(k.to_string(), v.to_string());
        }
        i += 1;
    }

    let worktree = worktree.ok_or_else(|| anyhow!("fake docker runner expected /work mount"))?;
    let shell_cmd = cmd
        .last()
        .ok_or_else(|| anyhow!("fake docker command missing shell payload"))?
        .to_string();

    run_command_to_log(
        &["sh".to_string(), "-lc".to_string(), shell_cmd],
        logfile,
        Some(Path::new(&worktree)),
        Some(&env_map),
    )
}

fn extract_mount_src(mount: &str) -> Option<String> {
    for part in mount.split(',') {
        if let Some(src) = part.strip_prefix("src=") {
            return Some(src.to_string());
        }
    }
    None
}

pub fn check_tool_exists(tool: &str) -> Result<()> {
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

pub fn ensure_docker_daemon() -> Result<()> {
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

pub fn ensure_orch_dirs() -> Result<()> {
    mkdirp(&runs_dir())?;
    mkdirp(&repos_dir())?;
    Ok(())
}

pub fn mkdirp(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))
}

pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        mkdirp(parent)?;
    }
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

pub fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn load_spec(path: &Path) -> Result<Spec> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    let spec = if path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        serde_json::from_str(&text).context("invalid JSON spec")?
    } else {
        serde_yaml::from_str(&text).context("invalid YAML spec")?
    };
    Ok(spec)
}

pub fn validate_spec(spec: &Spec) -> Result<()> {
    let version = spec.schema_version.unwrap_or(CURRENT_SPEC_VERSION);
    if version != CURRENT_SPEC_VERSION {
        bail!(
            "unsupported schema_version {version}; expected {}",
            CURRENT_SPEC_VERSION
        );
    }

    if spec.agents.is_empty() {
        bail!("spec must include non-empty 'agents' list");
    }

    if let Some(base_ref) = &spec.base_ref
        && base_ref.trim().is_empty()
    {
        bail!("base_ref cannot be empty");
    }
    if let Some(image) = &spec.image
        && image.trim().is_empty()
    {
        bail!("image cannot be empty");
    }

    if let Some(defaults) = &spec.defaults {
        if let Some(cpus) = &defaults.cpus
            && cpus.trim().is_empty()
        {
            bail!("defaults.cpus cannot be empty");
        }
        if let Some(memory) = &defaults.memory
            && memory.trim().is_empty()
        {
            bail!("defaults.memory cannot be empty");
        }
        if let Some(pids_limit) = defaults.pids_limit
            && pids_limit < 1
        {
            bail!("defaults.pids_limit must be >= 1");
        }
        if let Some(prefix) = &defaults.commit_prefix
            && prefix.trim().is_empty()
        {
            bail!("defaults.commit_prefix cannot be empty");
        }
    }

    if let Some(review) = &spec.review {
        for (idx, check) in review.required_checks.iter().enumerate() {
            if check.trim().is_empty() {
                bail!("review.required_checks[{idx}] cannot be empty");
            }
        }
    }

    let name_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("valid regex");
    let mut names = HashSet::new();
    for agent in &spec.agents {
        if agent.name.trim().is_empty() {
            bail!("agent.name is required");
        }
        if !name_re.is_match(&agent.name) {
            bail!(
                "agent.name '{}' contains invalid characters; use [A-Za-z0-9._-]",
                agent.name
            );
        }
        if !names.insert(agent.name.clone()) {
            bail!("duplicate agent name: {}", agent.name);
        }
        if agent.cmd.trim().is_empty() {
            bail!("agent.cmd is required for {}", agent.name);
        }
        if let Some(base_ref) = &agent.base_ref
            && base_ref.trim().is_empty()
        {
            bail!("agent.base_ref cannot be empty for {}", agent.name);
        }
        if let Some(image) = &agent.image
            && image.trim().is_empty()
        {
            bail!("agent.image cannot be empty for {}", agent.name);
        }
        if let Some(cpus) = &agent.cpus
            && cpus.trim().is_empty()
        {
            bail!("agent.cpus cannot be empty for {}", agent.name);
        }
        if let Some(memory) = &agent.memory
            && memory.trim().is_empty()
        {
            bail!("agent.memory cannot be empty for {}", agent.name);
        }
        if let Some(pids_limit) = agent.pids_limit
            && pids_limit < 1
        {
            bail!("agent.pids_limit must be >= 1 for {}", agent.name);
        }
        if let Some(prefix) = &agent.commit_prefix
            && prefix.trim().is_empty()
        {
            bail!("agent.commit_prefix cannot be empty for {}", agent.name);
        }
        if let Some(message) = &agent.commit_message
            && message.trim().is_empty()
        {
            bail!("agent.commit_message cannot be empty for {}", agent.name);
        }
        for env_key in agent.env.keys() {
            if env_key.trim().is_empty() {
                bail!("agent.env contains empty key for {}", agent.name);
            }
        }
        for (idx, check) in agent.required_checks.iter().enumerate() {
            if check.trim().is_empty() {
                bail!(
                    "agent.required_checks[{idx}] cannot be empty for {}",
                    agent.name
                );
            }
        }
    }

    Ok(())
}

pub fn sanitize_repo_key(repo: &str) -> String {
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

pub fn sanitize_container_name(name: &str) -> String {
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

pub fn ensure_hub(repo_input: &str, repo_key: &str, base_ref: &str) -> Result<PathBuf> {
    let hub_path = repos_dir().join(format!("{repo_key}.git"));
    if hub_path.exists() {
        if should_refresh_hub(repo_input, &hub_path, base_ref)? {
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
        }
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

fn should_refresh_hub(repo_input: &str, hub_path: &Path, base_ref: &str) -> Result<bool> {
    let repo_path = Path::new(repo_input);
    if !repo_path.exists() {
        // Remote sources always refresh.
        return Ok(true);
    }

    // For local repos, skip expensive mirror refresh when base_ref head matches.
    let ref_expr = format!("{base_ref}^{{commit}}");
    let source_head = run_cmd(
        vec![
            "git".to_string(),
            "-C".to_string(),
            repo_input.to_string(),
            "rev-parse".to_string(),
            "--verify".to_string(),
            ref_expr.clone(),
        ],
        None,
        false,
        None,
    )?;
    let hub_head = git_dir_cmd(
        hub_path,
        &["rev-parse".to_string(), "--verify".to_string(), ref_expr],
        false,
    )?;

    if source_head.code != 0 || hub_head.code != 0 {
        return Ok(true);
    }

    Ok(source_head.stdout.trim() != hub_head.stdout.trim())
}

pub fn create_run_id() -> String {
    let stamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let mut rng = rand::rng();
    let mut suffix = String::new();
    for _ in 0..6 {
        suffix.push_str(&format!("{:x}", rng.random_range(0..16)));
    }
    format!("{stamp}-{suffix}")
}

pub fn git_dir_cmd(git_dir: &Path, args: &[String], check: bool) -> Result<CmdOutput> {
    let mut cmd = vec![format!("--git-dir={}", git_dir.to_string_lossy())];
    cmd.extend_from_slice(args);
    let mut full = vec!["git".to_string()];
    full.extend(cmd);
    run_cmd(full, None, check, None)
}

pub fn resolve_ref(git_dir: &Path, reference: &str) -> Result<String> {
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

pub fn remove_worktree_if_exists(git_dir: &Path, worktree: &Path) -> Result<()> {
    prune_worktrees(git_dir);
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
    if worktree.exists() {
        let _ = fs::remove_dir_all(worktree);
    }
    prune_worktrees(git_dir);
    Ok(())
}

pub fn prune_worktrees(git_dir: &Path) {
    let _ = git_dir_cmd(
        git_dir,
        &[
            "worktree".to_string(),
            "prune".to_string(),
            "--expire".to_string(),
            "now".to_string(),
        ],
        false,
    );
}

pub fn ensure_agent_branch_worktree(
    git_dir: &Path,
    base_ref: &str,
    branch: &str,
    worktree: &Path,
) -> Result<String> {
    prune_worktrees(git_dir);
    remove_worktree_if_exists(git_dir, worktree)?;
    if let Some(parent) = worktree.parent() {
        mkdirp(parent)?;
    }
    git_dir_cmd(
        git_dir,
        &[
            "worktree".to_string(),
            "add".to_string(),
            "-B".to_string(),
            branch.to_string(),
            worktree.to_string_lossy().to_string(),
            base_ref.to_string(),
        ],
        true,
    )?;
    git_head(worktree)
}

fn current_uid_gid() -> (String, String) {
    let pair = UID_GID_CACHE.get_or_init(|| {
        let uid = run_cmd(vec!["id".to_string(), "-u".to_string()], None, false, None)
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "0".to_string());
        let gid = run_cmd(vec!["id".to_string(), "-g".to_string()], None, false, None)
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "0".to_string());
        (uid, gid)
    });
    (pair.0.clone(), pair.1.clone())
}

pub fn docker_command(opts: DockerCmdOptions) -> Result<Vec<String>> {
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
            "type=bind,src={},dst=/work",
            opts.worktree.canonicalize()?.to_string_lossy()
        ),
        "--mount".to_string(),
        format!(
            "type=bind,src={},dst=/out",
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

pub fn git_is_dirty(worktree: &Path) -> Result<bool> {
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

pub fn git_head(worktree: &Path) -> Result<String> {
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
        let after_head = git_head(worktree)?;
        return Ok(CommitInfo {
            committed: after_head != before_head,
            auto_committed: false,
            dirty_uncommitted: false,
            after_head,
        });
    }
    if !auto_commit {
        let after_head = git_head(worktree)?;
        return Ok(CommitInfo {
            committed: after_head != before_head,
            auto_committed: false,
            dirty_uncommitted: true,
            after_head,
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
    let after_head = git_head(worktree)?;
    Ok(CommitInfo {
        committed: after_head != before_head,
        auto_committed: true,
        dirty_uncommitted: false,
        after_head,
    })
}

pub fn read_result_json(out_dir: &Path) -> Result<Option<Value>> {
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

pub fn save_manifest(manifest: &RunManifest) -> Result<()> {
    let path = runs_dir().join(&manifest.run_id).join("run.json");
    write_json(&path, &serde_json::to_value(manifest)?)
}

pub fn repo_from_manifest(run_id: &str) -> Result<RunManifest> {
    let path = runs_dir().join(run_id).join("run.json");
    let text = fs::read_to_string(&path).with_context(|| format!("run not found: {run_id}"))?;
    serde_json::from_str(&text).with_context(|| format!("invalid run manifest: {}", path.display()))
}

pub fn list_runs() -> Result<Vec<String>> {
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

pub fn run_local_checks(
    worktree: &Path,
    commands: &[String],
    log_path: &Path,
) -> Result<Vec<Value>> {
    if let Some(parent) = log_path.parent() {
        mkdirp(parent)?;
    }
    let mut file = fs::File::create(log_path)?;
    let mut out = vec![];
    for command in commands {
        writeln!(file, "$ {command}")?;
        let code = run_command_to_existing_log(
            &["sh".to_string(), "-lc".to_string(), command.clone()],
            Some(worktree),
            None,
            &file,
        )?;
        writeln!(file, "\n[exit_code={code}]\n")?;
        out.push(json!({
            "command": command,
            "exit_code": code,
            "status": if code == 0 { "pass" } else { "fail" }
        }));
    }
    Ok(out)
}

pub fn parse_agent_entry(raw: &str) -> Result<(String, String)> {
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

#[derive(Debug)]
pub struct DockerCmdOptions {
    pub container_name: String,
    pub image: String,
    pub cmd: String,
    pub worktree: PathBuf,
    pub out_dir: PathBuf,
    pub env_map: HashMap<String, String>,
    pub cpus: String,
    pub memory: String,
    pub pids_limit: i64,
    pub needs_network: bool,
    pub read_only_rootfs: bool,
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

    #[test]
    fn reject_unsupported_schema_version() {
        let spec = Spec {
            schema_version: Some(CURRENT_SPEC_VERSION + 1),
            ..Spec::default()
        };
        let err = validate_spec(&spec).expect_err("expected schema validation to fail");
        assert!(err.to_string().contains("unsupported schema_version"));
    }
}
