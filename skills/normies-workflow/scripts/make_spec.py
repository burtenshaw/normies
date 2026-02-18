#!/usr/bin/env python3
"""
Generate a JSON spec for normies.

Usage example:
  ./scripts/make_spec.py \
    --output /tmp/normies-spec.json \
    --repo owner/repo \
    --agent "lint::npm ci && npm run lint" \
    --agent "test::npm test" \
    --check "git diff --check"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_agent(raw: str) -> dict[str, str]:
    if "::" not in raw:
        raise ValueError("agent must use format 'name::command'")
    name, cmd = raw.split("::", 1)
    name = name.strip()
    cmd = cmd.strip()
    if not name:
        raise ValueError("agent name cannot be empty")
    if not cmd:
        raise ValueError("agent command cannot be empty")
    return {"name": name, "cmd": cmd}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a JSON normies spec.")
    parser.add_argument("--output", required=True, help="Output JSON file path.")
    parser.add_argument("--repo", help="Optional repo (local path, URL, or owner/repo).")
    parser.add_argument("--base-ref", default="main", help="Base ref. Default: main")
    parser.add_argument("--image", default="ubuntu:24.04", help="Default container image.")
    parser.add_argument(
        "--agent",
        action="append",
        default=[],
        help="Agent in format 'name::command'. Repeat for multiple agents.",
    )
    parser.add_argument(
        "--network-agent",
        action="append",
        default=[],
        help="Agent name that needs network access. Repeatable.",
    )
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        help="Review required check command. Repeatable.",
    )
    parser.add_argument("--cpus", default="2", help="Default CPU limit.")
    parser.add_argument("--memory", default="4g", help="Default memory limit.")
    parser.add_argument("--pids-limit", type=int, default=256, help="Default pids limit.")
    parser.add_argument(
        "--auto-commit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable/disable orchestrator auto-commit.",
    )
    args = parser.parse_args()

    if not args.agent:
        parser.error("at least one --agent is required")

    try:
        agents = [parse_agent(item) for item in args.agent]
    except ValueError as exc:
        parser.error(str(exc))

    network_set = set(args.network_agent or [])
    for agent in agents:
        if agent["name"] in network_set:
            agent["needs_network"] = True

    spec: dict[str, object] = {
        "base_ref": args.base_ref,
        "image": args.image,
        "defaults": {
            "cpus": str(args.cpus),
            "memory": str(args.memory),
            "pids_limit": int(args.pids_limit),
            "needs_network": False,
            "auto_commit": bool(args.auto_commit),
            "read_only_rootfs": False,
            "commit_prefix": "agent",
        },
        "review": {
            "required_checks": list(args.check or []),
        },
        "agents": agents,
    }
    if args.repo:
        spec["repo"] = args.repo

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
