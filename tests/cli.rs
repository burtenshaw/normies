use assert_cmd::prelude::*;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git command failed to start");
    assert!(
        out.status.success(),
        "git command failed: {}\nstdout: {}\nstderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn init_repo(tmp: &TempDir) -> std::path::PathBuf {
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo dir");
    let status = Command::new("git")
        .arg("init")
        .arg("-b")
        .arg("main")
        .arg(&repo)
        .status()
        .expect("git init failed to start");
    assert!(status.success(), "git init failed");
    git(&repo, &["config", "user.name", "Tester"]);
    git(&repo, &["config", "user.email", "tester@example.com"]);
    fs::write(repo.join("README.md"), "hello\n").expect("write README");
    git(&repo, &["add", "README.md"]);
    git(&repo, &["commit", "-m", "init"]);
    repo
}

fn normies_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("normies"))
}

fn read_status(tmp: &TempDir, run_id: &str) -> serde_json::Value {
    let out = normies_cmd()
        .current_dir(tmp.path())
        .args(["status", "--run-id", run_id, "--json"])
        .output()
        .expect("status should start");
    assert!(
        out.status.success(),
        "status failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("status json")
}

#[test]
fn e2e_run_review_integrate_fake_docker() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "base_ref": "main",
            "review": { "required_checks": ["test -f CREATED_BY_AGENT.txt"] },
            "agents": [
                {
                    "name": "add-test-file",
                    "cmd": "echo agent-generated > CREATED_BY_AGENT.txt"
                }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-test-001";

    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
        ])
        .assert()
        .success();

    normies_cmd()
        .current_dir(tmp.path())
        .args(["review", "--run-id", run_id])
        .assert()
        .success();

    normies_cmd()
        .current_dir(tmp.path())
        .args(["integrate", "--run-id", run_id])
        .assert()
        .success();

    let integration_report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            tmp.path()
                .join(".orchestrator")
                .join("runs")
                .join(run_id)
                .join("integration")
                .join("integration.json"),
        )
        .expect("read integration report"),
    )
    .expect("parse integration report");
    assert!(
        integration_report
            .get("integration_branch")
            .and_then(serde_json::Value::as_str)
            == Some("orchestrator/integration/run-test-001"),
        "unexpected integration branch: {integration_report}"
    );
    assert!(
        integration_report
            .get("merged")
            .and_then(serde_json::Value::as_array)
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("add-test-file")))
            .unwrap_or(false),
        "expected merged agent entry in integration report: {integration_report}"
    );
}

#[test]
fn retry_failed_reruns_only_failed_agents() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "ok-agent", "cmd": "echo ok > OK.txt" },
                { "name": "bad-agent", "cmd": "echo fail >&2; exit 7" }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-retry-001";

    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
            "--jobs",
            "2",
            "--json",
        ])
        .assert()
        .success();

    let before = read_status(&tmp, run_id);
    let before_agents = before
        .get("agents")
        .and_then(serde_json::Value::as_array)
        .expect("agents array before retry");
    assert!(
        before_agents
            .iter()
            .any(
                |a| a.get("name").and_then(serde_json::Value::as_str) == Some("bad-agent")
                    && a.get("status").and_then(serde_json::Value::as_str) == Some("failed")
            ),
        "expected bad-agent to fail before retry: {before}"
    );

    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "ok-agent", "cmd": "echo ok > OK.txt" },
                { "name": "bad-agent", "cmd": "echo recovered > BAD.txt" }
            ]
        }))
        .expect("serialize updated spec"),
    )
    .expect("rewrite spec");

    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "retry", "--run-id", run_id, "--failed", "--jobs", "2", "--json",
        ])
        .assert()
        .success();

    let after = read_status(&tmp, run_id);
    let after_agents = after
        .get("agents")
        .and_then(serde_json::Value::as_array)
        .expect("agents array after retry");
    assert!(
        after_agents
            .iter()
            .any(
                |a| a.get("name").and_then(serde_json::Value::as_str) == Some("bad-agent")
                    && a.get("status").and_then(serde_json::Value::as_str) == Some("ok")
            ),
        "expected bad-agent to recover after retry: {after}"
    );
}

#[test]
fn make_spec_supports_no_auto_commit() {
    let tmp = TempDir::new().expect("tempdir");
    let output = tmp.path().join("spec.json");

    normies_cmd()
        .current_dir(tmp.path())
        .args([
            "make-spec",
            "--output",
            output.to_string_lossy().as_ref(),
            "--agent",
            "lint::echo lint",
            "--no-auto-commit",
        ])
        .assert()
        .success();

    let spec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).expect("read generated spec"))
            .expect("parse generated spec");
    assert_eq!(
        spec.get("defaults")
            .and_then(|v| v.get("auto_commit"))
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "expected defaults.auto_commit=false in generated spec: {spec}"
    );
}

#[test]
fn review_uses_latest_when_run_id_is_omitted() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "add-test-file", "cmd": "echo agent-generated > CREATED_BY_AGENT.txt" }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-latest-001";
    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
            "--json",
        ])
        .assert()
        .success();

    normies_cmd()
        .current_dir(tmp.path())
        .args(["review", "--json"])
        .assert()
        .success();
}

#[test]
fn logs_can_list_agents_without_agent_name() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "a1", "cmd": "echo a1 > A1.txt" },
                { "name": "a2", "cmd": "echo a2 > A2.txt" }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-logs-001";
    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
            "--json",
        ])
        .assert()
        .success();

    let out = normies_cmd()
        .current_dir(tmp.path())
        .args(["logs", "--latest", "--list-agents"])
        .output()
        .expect("logs should start");
    assert!(
        out.status.success(),
        "logs failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a1"),
        "expected a1 in logs output: {stdout}"
    );
    assert!(
        stdout.contains("a2"),
        "expected a2 in logs output: {stdout}"
    );
}

#[test]
fn status_json_includes_worktree_status_metadata() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "meta-agent", "cmd": "echo meta > META.txt" }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-status-meta-001";
    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
            "--json",
        ])
        .assert()
        .success();

    let status = read_status(&tmp, run_id);
    let run_dir = status
        .get("run_dir")
        .and_then(serde_json::Value::as_str)
        .expect("run_dir in status json");
    assert!(
        run_dir.contains(run_id),
        "expected run_dir to contain run id: {status}"
    );

    let agents = status
        .get("worktree_status")
        .and_then(|v| v.get("agents"))
        .and_then(serde_json::Value::as_array)
        .expect("worktree_status.agents array");
    assert!(
        agents.iter().any(|a| {
            a.get("name").and_then(serde_json::Value::as_str) == Some("meta-agent")
                && a.get("exists").and_then(serde_json::Value::as_bool) == Some(true)
        }),
        "expected worktree status entry for meta-agent: {status}"
    );
}

#[test]
fn integrate_json_includes_codex_handoff_metadata() {
    let tmp = TempDir::new().expect("tempdir");
    let repo = init_repo(&tmp);
    let spec_path = tmp.path().join("spec.json");
    fs::write(
        &spec_path,
        serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "base_ref": "main",
            "agents": [
                { "name": "codex-agent", "cmd": "echo codex > CODEX.txt" }
            ]
        }))
        .expect("serialize spec"),
    )
    .expect("write spec");

    let run_id = "run-codex-handoff-001";
    normies_cmd()
        .current_dir(tmp.path())
        .env("NORMIES_TEST_FAKE_DOCKER", "1")
        .args([
            "run",
            "--repo",
            repo.to_string_lossy().as_ref(),
            "--spec",
            spec_path.to_string_lossy().as_ref(),
            "--run-id",
            run_id,
            "--json",
        ])
        .assert()
        .success();

    normies_cmd()
        .current_dir(tmp.path())
        .args(["review", "--run-id", run_id, "--json"])
        .assert()
        .success();

    let out = normies_cmd()
        .current_dir(tmp.path())
        .args(["integrate", "--run-id", run_id, "--json"])
        .output()
        .expect("integrate should start");
    assert!(
        out.status.success(),
        "integrate failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("integrate json");

    let codex = report.get("codex").expect("codex section");
    let fetch = codex
        .get("fetch_integration_branch")
        .and_then(serde_json::Value::as_str)
        .expect("fetch command");
    assert!(
        fetch.contains("git fetch"),
        "expected fetch command in codex output: {report}"
    );
    let handoff_path = codex
        .get("handoff_markdown_path")
        .and_then(serde_json::Value::as_str)
        .expect("handoff markdown path");
    let handoff = PathBuf::from(handoff_path);
    let handoff = if handoff.is_absolute() {
        handoff
    } else {
        tmp.path().join(handoff)
    };
    assert!(
        handoff.exists(),
        "expected codex handoff markdown file at {}",
        handoff.display()
    );

    let merged_details = report
        .get("merged_details")
        .and_then(serde_json::Value::as_array)
        .expect("merged_details array");
    assert!(
        merged_details.iter().any(|item| {
            item.get("name").and_then(serde_json::Value::as_str) == Some("codex-agent")
                && item
                    .get("commit_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    >= 1
        }),
        "expected merged_details entry for codex-agent: {report}"
    );
}
