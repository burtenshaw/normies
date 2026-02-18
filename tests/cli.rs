use assert_cmd::prelude::*;
use serde_json::json;
use std::fs;
use std::path::Path;
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

#[test]
fn e2e_run_review_integrate_publish_fake_docker() {
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

    normies_cmd()
        .current_dir(tmp.path())
        .args(["publish", "--run-id", run_id])
        .assert()
        .success();

    let refs = git(&repo, &["show-ref"]);
    assert!(
        refs.contains("refs/heads/orchestrator/final/run-test-001"),
        "expected final branch ref in:\n{refs}"
    );
}
