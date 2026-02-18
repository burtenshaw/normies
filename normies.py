#!/usr/bin/env python3
"""
normies: Git-centric multi-agent orchestrator with mandatory Docker isolation.

All agent tasks run in Docker containers against isolated Git worktrees.
The orchestrator performs local review/integration, then can publish a final branch/PR.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import re
import shutil
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import click


ORCH_DIR = Path(".orchestrator")
RUNS_DIR = ORCH_DIR / "runs"
REPOS_DIR = ORCH_DIR / "repos"


DEFAULTS = {
    "base_ref": "main",
    "image": "ubuntu:24.04",
    "cpus": "2",
    "memory": "4g",
    "pids_limit": 256,
    "needs_network": False,
    "auto_commit": True,
    "read_only_rootfs": False,
    "commit_prefix": "agent",
    "required_checks": [],
}


class AgentCtlError(RuntimeError):
    pass


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    check: bool = True,
    capture: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode != 0:
        err = proc.stderr.strip() if proc.stderr else ""
        out = proc.stdout.strip() if proc.stdout else ""
        raise AgentCtlError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\nstdout: {out}\nstderr: {err}"
        )
    return proc


def run_logged(cmd: List[str], logfile: Path, cwd: Optional[Path] = None) -> int:
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("w", encoding="utf-8") as fh:
        fh.write(f"$ {' '.join(cmd)}\n")
        fh.flush()
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            fh.write(line)
        proc.wait()
        fh.write(f"\n[exit_code={proc.returncode}]\n")
        return proc.returncode


def check_tool_exists(tool: str) -> None:
    if shutil.which(tool):
        return
    raise AgentCtlError(f"required tool not found in PATH: {tool}")


def ensure_docker_daemon() -> None:
    proc = run_cmd(["docker", "info"], check=False, capture=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise AgentCtlError(f"docker daemon is not available: {detail}")


def sanitize_repo_key(repo: str) -> str:
    if os.path.exists(repo):
        raw = Path(repo).resolve().name
    else:
        raw = repo.rstrip("/").split("/")[-1]
    raw = raw.removesuffix(".git")
    raw = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    return raw or "repo"


def normalize_repo_input(repo: str) -> str:
    if os.path.exists(repo):
        return str(Path(repo).resolve())
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        return f"https://github.com/{repo}.git"
    return repo


def load_data(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)

    try:
        import yaml  # type: ignore
    except Exception as exc:
        raise AgentCtlError(
            "YAML spec requested but PyYAML is not installed. "
            "Use JSON spec or install PyYAML."
        ) from exc
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise AgentCtlError("spec must parse to a mapping/object")
    return data


def mkdirp(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    mkdirp(path.parent)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def git_dir_cmd(git_dir: Path, args: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_cmd(["git", f"--git-dir={git_dir}", *args], check=check)


def resolve_ref(git_dir: Path, ref: str) -> str:
    proc = git_dir_cmd(git_dir, ["rev-parse", "--verify", f"{ref}^{{commit}}"])
    return proc.stdout.strip()


def repo_from_manifest(run_id: str) -> Dict[str, Any]:
    run_path = RUNS_DIR / run_id / "run.json"
    if not run_path.exists():
        raise AgentCtlError(f"run not found: {run_id}")
    return read_json(run_path)


def save_manifest(manifest: Dict[str, Any]) -> None:
    run_id = manifest["run_id"]
    write_json(RUNS_DIR / run_id / "run.json", manifest)


def ensure_orch_dirs() -> None:
    mkdirp(RUNS_DIR)
    mkdirp(REPOS_DIR)


def ensure_hub(repo_input: str, repo_key: str) -> Path:
    hub_path = REPOS_DIR / f"{repo_key}.git"
    if hub_path.exists():
        run_cmd(["git", f"--git-dir={hub_path}", "remote", "update", "--prune"])
        return hub_path
    run_cmd(["git", "clone", "--mirror", repo_input, str(hub_path)])
    return hub_path


def create_run_id() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = "".join(random.choice("0123456789abcdef") for _ in range(6))
    return f"{stamp}-{suffix}"


def agent_default(spec: Dict[str, Any], key: str) -> Any:
    defaults = dict(DEFAULTS)
    defaults.update(spec.get("defaults") or {})
    if key == "required_checks":
        review_cfg = spec.get("review") or {}
        if "required_checks" in review_cfg:
            return review_cfg["required_checks"]
    return defaults.get(key)


def validate_spec(spec: Dict[str, Any]) -> None:
    if "agents" not in spec or not isinstance(spec["agents"], list) or not spec["agents"]:
        raise AgentCtlError("spec must include non-empty 'agents' list")
    names: set[str] = set()
    for agent in spec["agents"]:
        if not isinstance(agent, dict):
            raise AgentCtlError("each agent entry must be an object")
        name = agent.get("name")
        cmd = agent.get("cmd")
        if not name or not isinstance(name, str):
            raise AgentCtlError("agent.name is required")
        if name in names:
            raise AgentCtlError(f"duplicate agent name: {name}")
        names.add(name)
        if not cmd or not isinstance(cmd, str):
            raise AgentCtlError(f"agent.cmd is required for {name}")


def remove_worktree_if_exists(git_dir: Path, worktree: Path) -> None:
    if worktree.exists():
        git_dir_cmd(git_dir, ["worktree", "remove", "--force", str(worktree)], check=False)
        shutil.rmtree(worktree, ignore_errors=True)


def ensure_agent_branch_worktree(git_dir: Path, base_ref: str, branch: str, worktree: Path) -> str:
    remove_worktree_if_exists(git_dir, worktree)
    mkdirp(worktree.parent)
    git_dir_cmd(git_dir, ["worktree", "add", "--detach", str(worktree), base_ref])
    run_cmd(["git", "-C", str(worktree), "checkout", "-B", branch, base_ref])
    head = run_cmd(["git", "-C", str(worktree), "rev-parse", "HEAD"]).stdout.strip()
    return head


def docker_command(
    *,
    container_name: str,
    image: str,
    cmd: str,
    worktree: Path,
    out_dir: Path,
    env_map: Dict[str, str],
    cpus: str,
    memory: str,
    pids_limit: int,
    needs_network: bool,
    read_only_rootfs: bool,
) -> List[str]:
    uid = os.getuid()
    gid = os.getgid()
    full_cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--workdir",
        "/work",
        "--user",
        f"{uid}:{gid}",
        "--cpus",
        str(cpus),
        "--memory",
        str(memory),
        "--pids-limit",
        str(pids_limit),
        "--mount",
        f"type=bind,src={worktree.resolve()},dst=/work,rw",
        "--mount",
        f"type=bind,src={out_dir.resolve()},dst=/out,rw",
    ]
    if not needs_network:
        full_cmd += ["--network", "none"]
    if read_only_rootfs:
        full_cmd += ["--read-only", "--tmpfs", "/tmp", "--tmpfs", "/run"]
    for key, value in env_map.items():
        full_cmd += ["-e", f"{key}={value}"]
    full_cmd += [image, "sh", "-lc", cmd]
    return full_cmd


def git_is_dirty(worktree: Path) -> bool:
    proc = run_cmd(["git", "-C", str(worktree), "status", "--porcelain"])
    return bool(proc.stdout.strip())


def git_head(worktree: Path) -> str:
    return run_cmd(["git", "-C", str(worktree), "rev-parse", "HEAD"]).stdout.strip()


def ensure_commit_if_needed(
    *,
    worktree: Path,
    before_head: str,
    agent_name: str,
    commit_prefix: str,
    commit_message: Optional[str],
    auto_commit: bool,
) -> Dict[str, Any]:
    changed = git_is_dirty(worktree)
    if not changed:
        after = git_head(worktree)
        return {
            "committed": after != before_head,
            "auto_committed": False,
            "dirty_uncommitted": False,
            "after_head": after,
        }

    if not auto_commit:
        after = git_head(worktree)
        return {
            "committed": after != before_head,
            "auto_committed": False,
            "dirty_uncommitted": True,
            "after_head": after,
        }

    msg = commit_message or f"{commit_prefix}({agent_name}): apply automated changes"
    run_cmd(["git", "-C", str(worktree), "add", "-A"])
    run_cmd(
        [
            "git",
            "-C",
            str(worktree),
            "-c",
            f"user.name={agent_name}",
            "-c",
            f"user.email={agent_name}@local.agent",
            "commit",
            "-m",
            msg,
        ]
    )
    after = git_head(worktree)
    return {
        "committed": after != before_head,
        "auto_committed": True,
        "dirty_uncommitted": False,
        "after_head": after,
    }


def read_result_json(out_dir: Path) -> Optional[Dict[str, Any]]:
    p = out_dir / "result.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return None


def normalized_result(
    *,
    agent_name: str,
    exit_code: int,
    committed: bool,
    dirty_uncommitted: bool,
    existing: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    result = dict(existing) if existing else {}

    if exit_code != 0:
        result["status"] = "failed"
        result["summary"] = result.get("summary") or f"agent {agent_name} failed"
    elif dirty_uncommitted:
        result["status"] = "blocked"
        result["summary"] = (
            result.get("summary")
            or f"agent {agent_name} left uncommitted changes (set auto_commit=true or commit in-agent)"
        )
    elif "status" not in result:
        result["status"] = "ok" if committed else "no_change"
        result["summary"] = f"agent {agent_name} completed"
    result.setdefault("checks", [])
    result.setdefault("artifacts", [])
    result.setdefault("metrics", {})
    result.setdefault("summary", f"agent {agent_name} completed")
    result.setdefault("status", "no_change")
    return result


def list_runs() -> List[str]:
    if not RUNS_DIR.exists():
        return []
    return sorted([p.name for p in RUNS_DIR.iterdir() if p.is_dir()])


def cmd_run(args: SimpleNamespace) -> None:
    check_tool_exists("git")
    check_tool_exists("docker")
    ensure_docker_daemon()
    ensure_orch_dirs()

    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        raise AgentCtlError(f"spec file not found: {spec_path}")
    spec = load_data(spec_path)
    validate_spec(spec)

    repo_input = args.repo or spec.get("repo")
    if not repo_input:
        raise AgentCtlError("repo must be provided via --repo or spec.repo")

    normalized_repo = normalize_repo_input(repo_input)
    repo_key = sanitize_repo_key(normalized_repo)
    hub_path = ensure_hub(normalized_repo, repo_key)

    run_id = args.run_id or create_run_id()
    run_dir = RUNS_DIR / run_id
    if run_dir.exists():
        raise AgentCtlError(f"run_id already exists: {run_id}")
    mkdirp(run_dir / "agents")

    base_ref = spec.get("base_ref") or agent_default(spec, "base_ref")
    resolve_ref(hub_path, base_ref)

    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "repo_input": repo_input,
        "repo_resolved": normalized_repo,
        "repo_key": repo_key,
        "hub_path": str(hub_path.resolve()),
        "remote_name": "origin",
        "base_ref": base_ref,
        "integration_branch": f"orchestrator/integration/{run_id}",
        "final_branch": f"orchestrator/final/{run_id}",
        "spec_path": str(spec_path),
        "agents": [],
        "state": "running",
        "review": None,
        "integration": None,
        "published": None,
    }
    save_manifest(manifest)

    for agent_cfg in spec["agents"]:
        name = agent_cfg["name"]
        agent_dir = run_dir / "agents" / name
        worktree = agent_dir / "worktree"
        out_dir = agent_dir / "out"
        log_path = agent_dir / "docker.log"
        mkdirp(out_dir)

        agent_base_ref = agent_cfg.get("base_ref") or base_ref
        resolve_ref(hub_path, agent_base_ref)
        branch = f"agent/{run_id}/{name}"
        before_head = ensure_agent_branch_worktree(hub_path, agent_base_ref, branch, worktree)

        image = agent_cfg.get("image") or spec.get("image") or agent_default(spec, "image")
        cpus = str(agent_cfg.get("cpus") or agent_default(spec, "cpus"))
        memory = str(agent_cfg.get("memory") or agent_default(spec, "memory"))
        pids_limit = int(agent_cfg.get("pids_limit") or agent_default(spec, "pids_limit"))
        needs_network = bool(agent_cfg.get("needs_network", agent_default(spec, "needs_network")))
        read_only_rootfs = bool(
            agent_cfg.get("read_only_rootfs", agent_default(spec, "read_only_rootfs"))
        )
        auto_commit = bool(agent_cfg.get("auto_commit", agent_default(spec, "auto_commit")))
        commit_prefix = str(agent_cfg.get("commit_prefix") or agent_default(spec, "commit_prefix"))
        commit_message = agent_cfg.get("commit_message")
        env_map: Dict[str, str] = {
            "AGENT_NAME": name,
            "RUN_ID": run_id,
            "AGENT_BRANCH": branch,
            "AGENT_BASE_REF": agent_base_ref,
        }
        for k, v in (agent_cfg.get("env") or {}).items():
            env_map[str(k)] = str(v)

        container_name = f"agent-{run_id}-{re.sub(r'[^a-zA-Z0-9_.-]+', '-', name)}"
        dcmd = docker_command(
            container_name=container_name,
            image=image,
            cmd=agent_cfg["cmd"],
            worktree=worktree,
            out_dir=out_dir,
            env_map=env_map,
            cpus=cpus,
            memory=memory,
            pids_limit=pids_limit,
            needs_network=needs_network,
            read_only_rootfs=read_only_rootfs,
        )
        exit_code = run_logged(dcmd, logfile=log_path)

        commit_info = ensure_commit_if_needed(
            worktree=worktree,
            before_head=before_head,
            agent_name=name,
            commit_prefix=commit_prefix,
            commit_message=commit_message,
            auto_commit=auto_commit,
        )
        result_obj = normalized_result(
            agent_name=name,
            exit_code=exit_code,
            committed=bool(commit_info["committed"]),
            dirty_uncommitted=bool(commit_info["dirty_uncommitted"]),
            existing=read_result_json(out_dir),
        )
        write_json(out_dir / "result.json", result_obj)

        agent_state = {
            "name": name,
            "branch": branch,
            "base_ref": agent_base_ref,
            "before_head": before_head,
            "after_head": commit_info["after_head"],
            "committed": bool(commit_info["committed"]),
            "auto_committed": bool(commit_info["auto_committed"]),
            "dirty_uncommitted": bool(commit_info["dirty_uncommitted"]),
            "exit_code": exit_code,
            "status": result_obj.get("status", "unknown"),
            "summary": result_obj.get("summary", ""),
            "worktree": str(worktree.resolve()),
            "out_dir": str(out_dir.resolve()),
            "log_path": str(log_path.resolve()),
            "image": image,
            "cmd": agent_cfg["cmd"],
            "needs_network": needs_network,
            "read_only_rootfs": read_only_rootfs,
            "required_checks": list(agent_cfg.get("required_checks") or []),
        }
        manifest["agents"].append(agent_state)
        manifest["updated_at"] = now_iso()
        save_manifest(manifest)

    manifest["state"] = "ran"
    manifest["updated_at"] = now_iso()
    save_manifest(manifest)

    summary = {
        "run_id": run_id,
        "state": manifest["state"],
        "agents": [
            {
                "name": a["name"],
                "status": a["status"],
                "exit_code": a["exit_code"],
                "committed": a["committed"],
                "branch": a["branch"],
            }
            for a in manifest["agents"]
        ],
    }
    print_json(summary)


def cmd_status(args: SimpleNamespace) -> None:
    ensure_orch_dirs()
    if args.run_id:
        manifest = repo_from_manifest(args.run_id)
        print_json(manifest)
        return
    runs = list_runs()
    out = []
    for run_id in runs:
        m = repo_from_manifest(run_id)
        out.append(
            {
                "run_id": run_id,
                "created_at": m.get("created_at"),
                "updated_at": m.get("updated_at"),
                "state": m.get("state"),
                "repo_input": m.get("repo_input"),
            }
        )
    print_json(out)


def cmd_logs(args: SimpleNamespace) -> None:
    manifest = repo_from_manifest(args.run_id)
    selected = None
    for agent in manifest.get("agents", []):
        if agent["name"] == args.agent:
            selected = agent
            break
    if not selected:
        raise AgentCtlError(f"agent not found in run {args.run_id}: {args.agent}")
    log_path = Path(selected["log_path"])
    if not log_path.exists():
        raise AgentCtlError(f"log file not found: {log_path}")
    text = log_path.read_text(encoding="utf-8")
    print(text, end="")


def run_local_checks(worktree: Path, commands: List[str], logfile: Path) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    with logfile.open("w", encoding="utf-8") as fh:
        for command in commands:
            fh.write(f"$ {command}\n")
            fh.flush()
            proc = subprocess.run(
                ["sh", "-lc", command],
                cwd=str(worktree),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            fh.write(proc.stdout or "")
            fh.write(f"\n[exit_code={proc.returncode}]\n\n")
            results.append(
                {
                    "command": command,
                    "exit_code": proc.returncode,
                    "status": "pass" if proc.returncode == 0 else "fail",
                }
            )
    return results


def cmd_review(args: SimpleNamespace) -> None:
    manifest = repo_from_manifest(args.run_id)
    spec = load_data(Path(manifest["spec_path"]))
    global_checks = list(agent_default(spec, "required_checks") or [])

    run_dir = RUNS_DIR / args.run_id
    review_dir = run_dir / "review"
    mkdirp(review_dir)

    accepted: List[str] = []
    rejected: List[Dict[str, Any]] = []
    skipped: List[str] = []

    for agent in manifest.get("agents", []):
        name = agent["name"]
        status = agent.get("status")
        if status == "no_change":
            skipped.append(name)
            continue
        if status in {"failed", "blocked"}:
            rejected.append({"name": name, "reason": f"agent status is {status}"})
            continue
        worktree = Path(agent["worktree"])
        checks = list(global_checks)
        checks.extend(agent.get("required_checks") or [])
        checks = [c for c in checks if c.strip()]
        log_file = review_dir / f"{name}.log"
        check_results: List[Dict[str, Any]] = []
        if checks:
            check_results = run_local_checks(worktree, checks, log_file)
        failed_checks = [c for c in check_results if c["exit_code"] != 0]
        if failed_checks:
            rejected.append(
                {
                    "name": name,
                    "reason": "required checks failed",
                    "failed_checks": failed_checks,
                    "log_path": str(log_file.resolve()),
                }
            )
            continue
        accepted.append(name)

    report = {
        "run_id": args.run_id,
        "created_at": now_iso(),
        "accepted": accepted,
        "rejected": rejected,
        "skipped": skipped,
        "required_checks": global_checks,
    }
    write_json(review_dir / "review.json", report)
    manifest["review"] = report
    manifest["state"] = "reviewed"
    manifest["updated_at"] = now_iso()
    save_manifest(manifest)
    print_json(report)


def cmd_integrate(args: SimpleNamespace) -> None:
    manifest = repo_from_manifest(args.run_id)
    review = manifest.get("review")
    if not review:
        raise AgentCtlError("review report missing; run 'normies review --run-id <id>' first")

    hub_path = Path(manifest["hub_path"])
    run_id = manifest["run_id"]
    integration_branch = manifest["integration_branch"]
    base_ref = manifest["base_ref"]

    run_dir = RUNS_DIR / run_id
    integration_dir = run_dir / "integration"
    integration_wt = integration_dir / "worktree"
    mkdirp(integration_dir)

    remove_worktree_if_exists(hub_path, integration_wt)
    git_dir_cmd(hub_path, ["worktree", "add", "--detach", str(integration_wt), base_ref])
    run_cmd(["git", "-C", str(integration_wt), "checkout", "-B", integration_branch, base_ref])

    blocked: List[Dict[str, Any]] = []
    merged: List[str] = []

    accepted_names = set(review.get("accepted", []))
    ordered_agents = [a for a in manifest.get("agents", []) if a["name"] in accepted_names]
    for agent in ordered_agents:
        name = agent["name"]
        branch = agent["branch"]
        worktree = Path(agent["worktree"])

        # Rebase agent branch onto current integration branch.
        proc = run_cmd(
            ["git", "-C", str(worktree), "rebase", integration_branch],
            check=False,
            capture=True,
        )
        if proc.returncode != 0:
            run_cmd(["git", "-C", str(worktree), "rebase", "--abort"], check=False)
            blocked.append(
                {
                    "name": name,
                    "branch": branch,
                    "reason": "rebase conflict or failure",
                    "stderr": (proc.stderr or "").strip(),
                    "stdout": (proc.stdout or "").strip(),
                }
            )
            continue

        merge_proc = run_cmd(
            ["git", "-C", str(integration_wt), "merge", "--ff-only", branch],
            check=False,
            capture=True,
        )
        if merge_proc.returncode != 0:
            blocked.append(
                {
                    "name": name,
                    "branch": branch,
                    "reason": "ff-only merge failed after rebase",
                    "stderr": (merge_proc.stderr or "").strip(),
                    "stdout": (merge_proc.stdout or "").strip(),
                }
            )
            continue
        merged.append(name)

    integration_report = {
        "run_id": run_id,
        "created_at": now_iso(),
        "integration_branch": integration_branch,
        "base_ref": base_ref,
        "merged": merged,
        "blocked": blocked,
    }
    write_json(integration_dir / "integration.json", integration_report)
    manifest["integration"] = integration_report
    manifest["state"] = "integrated" if not blocked else "integrated_with_blocks"
    manifest["updated_at"] = now_iso()
    save_manifest(manifest)
    print_json(integration_report)


def gh_available() -> bool:
    return shutil.which("gh") is not None


def parse_owner_repo_from_remote(remote_url: str) -> Optional[str]:
    # Supports https://github.com/owner/repo.git and git@github.com:owner/repo.git
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?$", remote_url)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def cmd_publish(args: SimpleNamespace) -> None:
    manifest = repo_from_manifest(args.run_id)
    integration = manifest.get("integration")
    if not integration:
        raise AgentCtlError("integration report missing; run 'normies integrate --run-id <id>' first")

    hub_path = Path(manifest["hub_path"])
    remote_name = args.remote or manifest.get("remote_name", "origin")
    integration_branch = manifest["integration_branch"]
    final_branch = args.final_branch or manifest["final_branch"]

    push_ref = f"{integration_branch}:{final_branch}"
    push_proc = run_cmd(
        [
            "git",
            "-c",
            f"remote.{remote_name}.mirror=false",
            f"--git-dir={hub_path}",
            "push",
            remote_name,
            push_ref,
        ],
        check=False,
    )
    if push_proc.returncode != 0:
        raise AgentCtlError(
            f"failed to push final branch {final_branch}\n{(push_proc.stderr or '').strip()}"
        )

    publish_data: Dict[str, Any] = {
        "created_at": now_iso(),
        "remote": remote_name,
        "integration_branch": integration_branch,
        "final_branch": final_branch,
        "pushed": True,
        "pr": None,
    }

    if args.final_pr:
        if not gh_available():
            raise AgentCtlError("gh CLI not found; cannot create PR with --final-pr")
        remote_url = run_cmd(
            ["git", f"--git-dir={hub_path}", "remote", "get-url", remote_name]
        ).stdout.strip()
        owner_repo = parse_owner_repo_from_remote(remote_url)
        if not owner_repo:
            raise AgentCtlError(
                "could not infer GitHub owner/repo from remote URL; pass a GitHub remote"
            )
        base_branch = args.base_branch or manifest["base_ref"]
        title = args.title or f"orchestrator: final changes for run {args.run_id}"

        integration_info = manifest.get("integration") or {}
        merged = integration_info.get("merged", [])
        blocked = integration_info.get("blocked", [])
        body = textwrap.dedent(
            f"""
            Automated final PR for run `{args.run_id}`.

            - Integration branch: `{integration_branch}`
            - Final branch: `{final_branch}`
            - Base: `{base_branch}`
            - Merged agents: {', '.join(merged) if merged else 'none'}
            - Blocked agents: {len(blocked)}
            """
        ).strip()

        pr_proc = run_cmd(
            [
                "gh",
                "pr",
                "create",
                "--repo",
                owner_repo,
                "--head",
                final_branch,
                "--base",
                base_branch,
                "--title",
                title,
                "--body",
                body,
                "--draft",
            ],
            check=False,
        )
        if pr_proc.returncode != 0:
            publish_data["pr"] = {
                "created": False,
                "error": (pr_proc.stderr or pr_proc.stdout or "").strip(),
            }
        else:
            publish_data["pr"] = {
                "created": True,
                "url": pr_proc.stdout.strip(),
                "repo": owner_repo,
            }

    manifest["published"] = publish_data
    manifest["state"] = "published"
    manifest["updated_at"] = now_iso()
    save_manifest(manifest)
    print_json(publish_data)


def cmd_cleanup(args: SimpleNamespace) -> None:
    manifest = repo_from_manifest(args.run_id)
    hub_path = Path(manifest["hub_path"])
    run_dir = RUNS_DIR / args.run_id

    # Remove integration worktree first.
    integration_wt = run_dir / "integration" / "worktree"
    if integration_wt.exists():
        git_dir_cmd(hub_path, ["worktree", "remove", "--force", str(integration_wt)], check=False)
        shutil.rmtree(integration_wt, ignore_errors=True)

    # Remove agent worktrees.
    for agent in manifest.get("agents", []):
        wt = Path(agent["worktree"])
        if wt.exists():
            git_dir_cmd(hub_path, ["worktree", "remove", "--force", str(wt)], check=False)
            shutil.rmtree(wt, ignore_errors=True)

    if args.remove_run_dir:
        shutil.rmtree(run_dir, ignore_errors=True)

    out = {"run_id": args.run_id, "removed_worktrees": True, "removed_run_dir": args.remove_run_dir}
    print_json(out)


def run_with_error_handling(func: Any, args: SimpleNamespace) -> None:
    try:
        func(args)
    except AgentCtlError as exc:
        raise click.ClickException(str(exc)) from exc
    except KeyboardInterrupt as exc:
        raise click.Abort() from exc


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli() -> None:
    """Git-centric multi-agent orchestrator with Docker-isolated execution."""


@cli.command("run")
@click.option("--repo", help="Git remote URL, owner/repo shorthand, or local path.")
@click.option(
    "--spec",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to YAML/JSON run spec.",
)
@click.option("--run-id", help="Optional explicit run id.")
def run_command(repo: Optional[str], spec: Path, run_id: Optional[str]) -> None:
    args = SimpleNamespace(repo=repo, spec=str(spec), run_id=run_id)
    run_with_error_handling(cmd_run, args)


@cli.command("status")
@click.option("--run-id", help="Run id to inspect.")
def status_command(run_id: Optional[str]) -> None:
    args = SimpleNamespace(run_id=run_id)
    run_with_error_handling(cmd_status, args)


@cli.command("logs")
@click.option("--run-id", required=True, help="Run id.")
@click.option("--agent", required=True, help="Agent name.")
def logs_command(run_id: str, agent: str) -> None:
    args = SimpleNamespace(run_id=run_id, agent=agent)
    run_with_error_handling(cmd_logs, args)


@cli.command("review")
@click.option("--run-id", required=True, help="Run id.")
def review_command(run_id: str) -> None:
    args = SimpleNamespace(run_id=run_id)
    run_with_error_handling(cmd_review, args)


@cli.command("integrate")
@click.option("--run-id", required=True, help="Run id.")
def integrate_command(run_id: str) -> None:
    args = SimpleNamespace(run_id=run_id)
    run_with_error_handling(cmd_integrate, args)


@cli.command("publish")
@click.option("--run-id", required=True, help="Run id.")
@click.option("--remote", help="Remote name, defaults to origin.")
@click.option("--final-branch", help="Override final branch name.")
@click.option("--final-pr", is_flag=True, help="Open final PR via gh CLI.")
@click.option("--base-branch", help="PR base branch, defaults to run base_ref.")
@click.option("--title", help="PR title override.")
def publish_command(
    run_id: str,
    remote: Optional[str],
    final_branch: Optional[str],
    final_pr: bool,
    base_branch: Optional[str],
    title: Optional[str],
) -> None:
    args = SimpleNamespace(
        run_id=run_id,
        remote=remote,
        final_branch=final_branch,
        final_pr=final_pr,
        base_branch=base_branch,
        title=title,
    )
    run_with_error_handling(cmd_publish, args)


@cli.command("cleanup")
@click.option("--run-id", required=True, help="Run id.")
@click.option(
    "--remove-run-dir",
    is_flag=True,
    help="Also remove .orchestrator/runs/<run_id> directory.",
)
def cleanup_command(run_id: str, remove_run_dir: bool) -> None:
    args = SimpleNamespace(run_id=run_id, remove_run_dir=remove_run_dir)
    run_with_error_handling(cmd_cleanup, args)


if __name__ == "__main__":
    cli()
