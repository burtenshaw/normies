from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import normies


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def init_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    git(repo, "config", "user.name", "Tester")
    git(repo, "config", "user.email", "tester@example.com")
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "init")
    return repo


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def mount_src(mount: str) -> str:
    src = ""
    for part in mount.split(","):
        if part.startswith("src="):
            src = part[4:]
    if not src:
        raise AssertionError(f"mount src not found: {mount}")
    return src


def fake_run_logged(cmd: list[str], logfile: Path, cwd: Path | None = None) -> int:
    del cwd
    worktree: str | None = None
    env = os.environ.copy()
    for i, token in enumerate(cmd):
        if token == "--mount":
            mount = cmd[i + 1]
            if "dst=/work" in mount:
                worktree = mount_src(mount)
        if token == "-e":
            k, v = cmd[i + 1].split("=", 1)
            env[k] = v

    assert worktree, "fake docker runner expected /work mount"
    shell_cmd = cmd[-1]
    proc = subprocess.run(
        ["sh", "-lc", shell_cmd],
        cwd=worktree,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    logfile.parent.mkdir(parents=True, exist_ok=True)
    logfile.write_text((proc.stdout or "") + f"\n[exit_code={proc.returncode}]\n", encoding="utf-8")
    return proc.returncode


def test_normalize_repo_input_slug() -> None:
    assert normies.normalize_repo_input("owner/repo") == "https://github.com/owner/repo.git"


def test_parse_owner_repo_from_remote() -> None:
    assert normies.parse_owner_repo_from_remote("https://github.com/acme/proj.git") == "acme/proj"
    assert normies.parse_owner_repo_from_remote("git@github.com:acme/proj.git") == "acme/proj"
    assert normies.parse_owner_repo_from_remote("https://example.com/acme/proj.git") is None


def test_normalized_result_exit_code_overrides_existing() -> None:
    out = normies.normalized_result(
        agent_name="a1",
        exit_code=9,
        committed=True,
        dirty_uncommitted=False,
        existing={"status": "ok", "summary": "done"},
    )
    assert out["status"] == "failed"
    assert "summary" in out


def test_ensure_commit_if_needed_auto_commit(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    before = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    out = normies.ensure_commit_if_needed(
        worktree=repo,
        before_head=before,
        agent_name="agent-x",
        commit_prefix="agent",
        commit_message=None,
        auto_commit=True,
    )
    assert out["committed"] is True
    assert out["auto_committed"] is True
    assert out["dirty_uncommitted"] is False
    assert out["after_head"] != before


def test_ensure_commit_if_needed_without_auto_commit_marks_dirty(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    before = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "README.md").write_text("changed-again\n", encoding="utf-8")
    out = normies.ensure_commit_if_needed(
        worktree=repo,
        before_head=before,
        agent_name="agent-y",
        commit_prefix="agent",
        commit_message=None,
        auto_commit=False,
    )
    assert out["committed"] is False
    assert out["auto_committed"] is False
    assert out["dirty_uncommitted"] is True


def test_cmd_run_review_integrate_publish_with_fake_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    repo = init_repo(tmp_path)
    spec = {
        "base_ref": "main",
        "review": {"required_checks": ["test -f CREATED_BY_AGENT.txt"]},
        "agents": [
            {
                "name": "add-test-file",
                "cmd": "echo agent-generated > CREATED_BY_AGENT.txt",
            }
        ],
    }
    spec_path = tmp_path / "spec.json"
    write_json(spec_path, spec)

    monkeypatch.setattr(normies, "ensure_docker_daemon", lambda: None)
    monkeypatch.setattr(normies, "run_logged", fake_run_logged)

    run_id = "run-test-001"
    normies.cmd_run(SimpleNamespace(repo=str(repo), spec=str(spec_path), run_id=run_id))
    manifest = normies.repo_from_manifest(run_id)
    assert manifest["state"] == "ran"
    assert manifest["agents"][0]["status"] == "ok"
    assert manifest["agents"][0]["committed"] is True

    normies.cmd_review(SimpleNamespace(run_id=run_id))
    manifest = normies.repo_from_manifest(run_id)
    assert manifest["review"]["accepted"] == ["add-test-file"]
    assert manifest["review"]["rejected"] == []

    normies.cmd_integrate(SimpleNamespace(run_id=run_id))
    manifest = normies.repo_from_manifest(run_id)
    assert manifest["integration"]["merged"] == ["add-test-file"]
    assert manifest["integration"]["blocked"] == []

    normies.cmd_publish(
        SimpleNamespace(
            run_id=run_id,
            remote=None,
            final_branch=None,
            final_pr=False,
            base_branch=None,
            title=None,
        )
    )
    manifest = normies.repo_from_manifest(run_id)
    assert manifest["state"] == "published"
    assert manifest["published"]["pushed"] is True

    refs = git(repo, "show-ref").stdout
    assert f"refs/heads/{manifest['final_branch']}" in refs
