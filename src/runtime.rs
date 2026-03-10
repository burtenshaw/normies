use crate::models::{
    BindMountSpec, CURRENT_SPEC_VERSION, CmdOutput, CommitInfo, RunManifest, Spec,
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use rand::Rng;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

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
    let mut worktree: Option<PathBuf> = None;
    let mut mounts = vec![];
    let mut env_map: HashMap<String, String> = HashMap::new();
    let mut i = 0usize;
    while i < cmd.len() {
        if cmd[i] == "--mount"
            && i + 1 < cmd.len()
            && let Some(mount) = parse_mount_spec(&cmd[i + 1])
        {
            if mount.dst == "/work" {
                worktree = Some(mount.src.clone());
            }
            mounts.push(mount);
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
    rewrite_fake_mount_env(&mut env_map, &mounts);
    let shell_cmd = cmd
        .last()
        .ok_or_else(|| anyhow!("fake docker command missing shell payload"))?
        .to_string();

    let overlay_mounts = worktree_overlay_mounts(&mounts);
    let overlays_guard = if overlay_mounts.is_empty() {
        None
    } else {
        Some(FakeOverlayGuard::apply(&worktree, &overlay_mounts)?)
    };

    run_command_to_log(
        &["sh".to_string(), "-lc".to_string(), shell_cmd],
        logfile,
        Some(&worktree),
        Some(&env_map),
    )
    .inspect(|_| {
        drop(overlays_guard);
    })
}

fn rewrite_fake_mount_env(env_map: &mut HashMap<String, String>, mounts: &[BindMountSpec]) {
    let mut ordered = mounts.to_vec();
    ordered.sort_by_key(|mount| std::cmp::Reverse(mount.dst.len()));

    for value in env_map.values_mut() {
        let Some(rewritten) = ordered
            .iter()
            .find_map(|mount| rewrite_fake_path(value, Path::new(&mount.dst), &mount.src))
        else {
            continue;
        };
        *value = rewritten;
    }
}

fn extract_mount_src(mount: &str) -> Option<String> {
    for part in mount.split(',') {
        if let Some(src) = part.strip_prefix("src=") {
            return Some(src.to_string());
        }
    }
    None
}

fn extract_mount_dst(mount: &str) -> Option<String> {
    for part in mount.split(',') {
        if let Some(dst) = part.strip_prefix("dst=") {
            return Some(dst.to_string());
        }
    }
    None
}

fn parse_mount_spec(raw: &str) -> Option<BindMountSpec> {
    Some(BindMountSpec {
        src: PathBuf::from(extract_mount_src(raw)?),
        dst: extract_mount_dst(raw)?,
    })
}

fn rewrite_fake_path(value: &str, dst: &Path, src: &Path) -> Option<String> {
    let value_path = Path::new(value);
    let suffix = value_path.strip_prefix(dst).ok()?;
    Some(src.join(suffix).to_string_lossy().to_string())
}

fn worktree_overlay_mounts(mounts: &[BindMountSpec]) -> Vec<BindMountSpec> {
    mounts
        .iter()
        .filter(|mount| mount.dst.starts_with("/work/"))
        .cloned()
        .collect()
}

struct FakeOverlayGuard {
    backups: Vec<(PathBuf, Option<PathBuf>)>,
    temp_dirs: Vec<PathBuf>,
}

impl FakeOverlayGuard {
    fn apply(worktree: &Path, mounts: &[BindMountSpec]) -> Result<Self> {
        let mut guard = Self {
            backups: vec![],
            temp_dirs: vec![],
        };
        for mount in mounts {
            let rel = Path::new(&mount.dst)
                .strip_prefix("/work")
                .expect("overlay dst already filtered")
                .to_path_buf();
            let rel = if rel.as_os_str().is_empty() {
                continue;
            } else {
                rel
            };
            let target = worktree.join(rel);
            guard.backup_and_replace(&target, &mount.src)?;
        }
        Ok(guard)
    }

    fn backup_and_replace(&mut self, target: &Path, src: &Path) -> Result<()> {
        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("overlay target must have parent: {}", target.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create overlay parent {}", parent.display()))?;

        let backup_dir = temp_backup_dir(parent)?;
        let backup_path = backup_dir.join("backup");
        let prior = if target.exists() {
            fs::rename(target, &backup_path).with_context(|| {
                format!(
                    "failed to move fake docker overlay target {} aside",
                    target.display()
                )
            })?;
            Some(backup_path)
        } else {
            None
        };
        self.temp_dirs.push(backup_dir);
        copy_path(src, target)?;
        self.backups.push((target.to_path_buf(), prior));
        Ok(())
    }
}

impl Drop for FakeOverlayGuard {
    fn drop(&mut self) {
        for (target, prior) in self.backups.iter().rev() {
            if target.is_dir() {
                let _ = fs::remove_dir_all(target);
            } else if target.exists() {
                let _ = fs::remove_file(target);
            }
            if let Some(prior_path) = prior {
                let _ = fs::rename(prior_path, target);
            }
        }
        for dir in self.temp_dirs.iter().rev() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn temp_backup_dir(parent: &Path) -> Result<PathBuf> {
    let mut rng = rand::rng();
    for _ in 0..16 {
        let candidate = parent.join(format!(
            ".normies-fake-overlay-{}-{:08x}",
            std::process::id(),
            rng.random::<u32>()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create fake docker backup dir {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    bail!("failed to allocate fake docker backup dir after repeated collisions")
}

fn copy_path(src: &Path, dst: &Path) -> Result<()> {
    if src.is_dir() {
        copy_dir_all(src, dst)
    } else {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(src, dst).with_context(|| {
            format!(
                "failed to copy fake docker overlay {} -> {}",
                src.display(),
                dst.display()
            )
        })?;
        Ok(())
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;
    for entry in
        fs::read_dir(src).with_context(|| format!("failed to read dir {}", src.display()))?
    {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            fs::copy(&from, &to).with_context(|| {
                format!(
                    "failed to copy fake docker overlay {} -> {}",
                    from.display(),
                    to.display()
                )
            })?;
        }
    }
    Ok(())
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

    if let Some(gateway) = &spec.a2a_gateway {
        if gateway.transport.trim().is_empty() {
            bail!("a2a_gateway.transport cannot be empty");
        }
        if !gateway.transport.eq_ignore_ascii_case("uds") {
            bail!(
                "a2a_gateway.transport '{}' is not supported; only 'uds' is currently supported",
                gateway.transport
            );
        }
        if gateway.auth.trim().is_empty() {
            bail!("a2a_gateway.auth cannot be empty");
        }
        if !gateway.auth.eq_ignore_ascii_case("bearer") {
            bail!(
                "a2a_gateway.auth '{}' is not supported; only 'bearer' is currently supported",
                gateway.auth
            );
        }
        if gateway.bind_timeout_ms == 0 {
            bail!("a2a_gateway.bind_timeout_ms must be > 0");
        }
        if gateway.request_timeout_ms == 0 {
            bail!("a2a_gateway.request_timeout_ms must be > 0");
        }
        if gateway.stream_idle_timeout_ms == 0 {
            bail!("a2a_gateway.stream_idle_timeout_ms must be > 0");
        }
        if gateway.max_payload_bytes == 0 {
            bail!("a2a_gateway.max_payload_bytes must be > 0");
        }
    }

    let name_re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("valid regex");
    let mut names = HashSet::new();
    let mut serving_agents = 0usize;
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
        if let Some(a2a) = &agent.a2a {
            if a2a.serve {
                serving_agents += 1;
            }
            if let Some(description) = &a2a.description
                && description.trim().is_empty()
            {
                bail!("agent.a2a.description cannot be empty for {}", agent.name);
            }

            let mut skill_ids = HashSet::new();
            for skill in &a2a.skills {
                if skill.id.trim().is_empty() {
                    bail!("agent.a2a.skills.id cannot be empty for {}", agent.name);
                }
                if !name_re.is_match(&skill.id) {
                    bail!(
                        "agent.a2a.skills.id '{}' contains invalid characters for {}",
                        skill.id,
                        agent.name
                    );
                }
                if !skill_ids.insert(skill.id.clone()) {
                    bail!(
                        "duplicate agent.a2a.skills.id '{}' for {}",
                        skill.id,
                        agent.name
                    );
                }
                if skill.name.trim().is_empty() {
                    bail!(
                        "agent.a2a.skills.name cannot be empty for {} ({})",
                        agent.name,
                        skill.id
                    );
                }
                if skill.description.trim().is_empty() {
                    bail!(
                        "agent.a2a.skills.description cannot be empty for {} ({})",
                        agent.name,
                        skill.id
                    );
                }
                for tag in &skill.tags {
                    if tag.trim().is_empty() {
                        bail!(
                            "agent.a2a.skills.tags cannot contain empty values for {} ({})",
                            agent.name,
                            skill.id
                        );
                    }
                }
                for example in &skill.examples {
                    if example.trim().is_empty() {
                        bail!(
                            "agent.a2a.skills.examples cannot contain empty values for {} ({})",
                            agent.name,
                            skill.id
                        );
                    }
                }
            }
        }
    }

    if spec
        .a2a_gateway
        .as_ref()
        .map(|cfg| cfg.enabled)
        .unwrap_or(false)
        && serving_agents == 0
    {
        bail!("a2a_gateway.enabled=true requires at least one agent with a2a.serve=true");
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
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    repo.hash(&mut hasher);
    let suffix = format!("{:016x}", hasher.finish());
    let prefix = if cleaned.is_empty() {
        "repo".to_string()
    } else {
        cleaned
    };
    format!("{prefix}-{suffix}")
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

pub fn ensure_hub(repo_input: &str, repo_key: &str, refs: &[String]) -> Result<PathBuf> {
    let hub_path = repos_dir().join(format!("{repo_key}.git"));
    if hub_path.exists() {
        ensure_hub_origin(repo_input, &hub_path)?;
        refresh_hub_if_needed(repo_input, &hub_path, refs)?;
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

pub fn refresh_hub_if_needed(repo_input: &str, hub_path: &Path, refs: &[String]) -> Result<()> {
    if should_refresh_hub(repo_input, hub_path, refs)? {
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
    Ok(())
}

fn ensure_hub_origin(repo_input: &str, hub_path: &Path) -> Result<()> {
    let expected = normalize_repo_input(repo_input).unwrap_or_else(|_| repo_input.to_string());
    let remote_out = git_dir_cmd(
        hub_path,
        &[
            "config".to_string(),
            "--get".to_string(),
            "remote.origin.url".to_string(),
        ],
        false,
    )?;
    if remote_out.code != 0 {
        bail!(
            "existing hub mirror {} is missing remote.origin.url",
            hub_path.display()
        );
    }
    let actual_raw = remote_out.stdout.trim();
    let actual = normalize_repo_input(actual_raw).unwrap_or_else(|_| actual_raw.to_string());
    if actual != expected {
        bail!(
            "existing hub mirror {} points to {} but expected {}",
            hub_path.display(),
            actual,
            expected
        );
    }
    Ok(())
}

fn should_refresh_hub(repo_input: &str, hub_path: &Path, refs: &[String]) -> Result<bool> {
    let repo_path = Path::new(repo_input);
    if !repo_path.exists() {
        // Remote sources always refresh.
        return Ok(true);
    }

    let mut saw_ref = false;
    for reference in refs {
        if reference.trim().is_empty() {
            continue;
        }
        saw_ref = true;
        let ref_expr = format!("{reference}^{{commit}}");
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

        if source_head.stdout.trim() != hub_head.stdout.trim() {
            return Ok(true);
        }
    }

    if !saw_ref {
        return Ok(true);
    }

    Ok(false)
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
    if let Some(gateway_dir) = &opts.gateway_dir {
        cmd.push("--mount".to_string());
        cmd.push(format!(
            "type=bind,src={},dst=/gateway",
            gateway_dir.canonicalize()?.to_string_lossy()
        ));
    }
    for mount in opts.extra_mounts {
        cmd.push("--mount".to_string());
        cmd.push(format!(
            "type=bind,src={},dst={}",
            mount.src.canonicalize()?.to_string_lossy(),
            mount.dst
        ));
    }
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
    pub gateway_dir: Option<PathBuf>,
    pub extra_mounts: Vec<BindMountSpec>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn git(repo: &Path, args: &[&str]) -> CmdOutput {
        run_cmd(
            std::iter::once("git".to_string())
                .chain(std::iter::once("-C".to_string()))
                .chain(std::iter::once(repo.to_string_lossy().to_string()))
                .chain(args.iter().map(|arg| arg.to_string()))
                .collect(),
            None,
            true,
            None,
        )
        .expect("git command")
    }

    fn init_repo(tmp: &TempDir, name: &str) -> PathBuf {
        let repo = tmp.path().join(name);
        fs::create_dir_all(&repo).expect("create repo dir");
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Tester"]);
        git(&repo, &["config", "user.email", "tester@example.com"]);
        fs::write(repo.join("README.md"), format!("{name}\n")).expect("write README");
        git(&repo, &["add", "README.md"]);
        git(&repo, &["commit", "-m", "init"]);
        repo
    }

    #[test]
    fn normalize_slug_to_https() {
        let got = normalize_repo_input("owner/repo").expect("normalize");
        assert_eq!(got, "https://github.com/owner/repo.git");
    }

    #[test]
    fn sanitize_repo_key_distinguishes_same_basename_sources() {
        let a = sanitize_repo_key("/tmp/one/repo");
        let b = sanitize_repo_key("/var/tmp/two/repo");
        assert_ne!(a, b);
        assert!(a.starts_with("repo-"));
        assert!(b.starts_with("repo-"));
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

    #[test]
    fn reject_non_uds_gateway_transport() {
        let spec: Spec = serde_json::from_value(json!({
            "schema_version": CURRENT_SPEC_VERSION,
            "a2a_gateway": {
                "enabled": true,
                "transport": "tcp"
            },
            "agents": [
                {
                    "name": "agent-1",
                    "cmd": "echo ok",
                    "a2a": { "serve": true }
                }
            ]
        }))
        .expect("spec");
        let err = validate_spec(&spec).expect_err("expected transport validation to fail");
        assert!(
            err.to_string()
                .contains("only 'uds' is currently supported")
        );
    }

    #[test]
    fn reject_enabled_gateway_without_serving_agent() {
        let spec: Spec = serde_json::from_value(json!({
            "schema_version": CURRENT_SPEC_VERSION,
            "a2a_gateway": {
                "enabled": true
            },
            "agents": [
                {
                    "name": "agent-1",
                    "cmd": "echo ok",
                    "a2a": { "serve": false }
                }
            ]
        }))
        .expect("spec");
        let err = validate_spec(&spec).expect_err("expected serving agent validation to fail");
        assert!(
            err.to_string()
                .contains("a2a_gateway.enabled=true requires at least one agent")
        );
    }

    #[test]
    fn reject_duplicate_agent_skill_ids() {
        let spec: Spec = serde_json::from_value(json!({
            "schema_version": CURRENT_SPEC_VERSION,
            "agents": [
                {
                    "name": "agent-1",
                    "cmd": "echo ok",
                    "a2a": {
                        "serve": true,
                        "skills": [
                            {"id": "skill-1", "name": "s1", "description": "one"},
                            {"id": "skill-1", "name": "s2", "description": "two"}
                        ]
                    }
                }
            ]
        }))
        .expect("spec");
        let err = validate_spec(&spec).expect_err("expected duplicate skill id validation to fail");
        assert!(err.to_string().contains("duplicate agent.a2a.skills.id"));
    }

    #[test]
    fn ensure_hub_refreshes_when_non_default_ref_changes() {
        let tmp = TempDir::new().expect("tempdir");
        let orch = tmp.path().join("orch");
        let repo = init_repo(&tmp, "repo");
        unsafe {
            std::env::set_var(ORCH_DIR_ENV, &orch);
        }
        ensure_orch_dirs().expect("orch dirs");

        let repo_input = normalize_repo_input(repo.to_string_lossy().as_ref()).expect("normalize");
        let repo_key = sanitize_repo_key(&repo_input);

        let refs = vec!["main".to_string()];
        let hub_path = ensure_hub(&repo_input, &repo_key, &refs).expect("ensure initial hub");
        assert!(resolve_ref(&hub_path, "main").is_ok());
        assert!(resolve_ref(&hub_path, "feature").is_err());

        git(&repo, &["checkout", "-b", "feature"]);
        fs::write(repo.join("FEATURE.txt"), "feature\n").expect("write feature file");
        git(&repo, &["add", "FEATURE.txt"]);
        git(&repo, &["commit", "-m", "feature"]);

        let refs = vec!["main".to_string(), "feature".to_string()];
        refresh_hub_if_needed(&repo_input, &hub_path, &refs).expect("refresh hub");
        assert!(resolve_ref(&hub_path, "feature").is_ok());
        unsafe {
            std::env::remove_var(ORCH_DIR_ENV);
        }
    }
}
