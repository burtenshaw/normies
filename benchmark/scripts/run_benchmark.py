#!/usr/bin/env python3
"""Run normies benchmark experiments across CPU core allocations."""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "benchmark"
ARTIFACTS_DIR = BENCH_DIR / "artifacts"
RESULTS_DIR = BENCH_DIR / "results"


@dataclass
class TimedResult:
    seconds: float
    stdout: str
    stderr: str


def run_cmd(cmd: list[str], *, env: dict[str, str] | None = None, cwd: pathlib.Path | None = None) -> TimedResult:
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        env=env,
        text=True,
        capture_output=True,
    )
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return TimedResult(seconds=elapsed, stdout=proc.stdout, stderr=proc.stderr)


def ensure_tools() -> None:
    for tool in ("git", "docker", "cargo"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required tool not found in PATH: {tool}")


def ensure_release_binary() -> pathlib.Path:
    print("[setup] building release binary")
    run_cmd(["cargo", "build", "--release"])
    binary = ROOT / "target" / "release" / "normies"
    if not binary.exists():
        raise RuntimeError(f"normies binary missing at {binary}")
    return binary


def ensure_docker_image(image: str) -> None:
    print(f"[setup] ensuring docker image {image}")
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
    )
    if inspect.returncode == 0:
        return
    run_cmd(["docker", "pull", image])


def init_repo(repo_dir: pathlib.Path) -> pathlib.Path:
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)
    run_cmd(["git", "init", "-b", "main", str(repo_dir)], cwd=ROOT)
    run_cmd(["git", "-C", str(repo_dir), "config", "user.name", "Benchmark Bot"])
    run_cmd(["git", "-C", str(repo_dir), "config", "user.email", "benchmark@local"])

    (repo_dir / "README.md").write_text("benchmark repo\n", encoding="utf-8")
    (repo_dir / "data").mkdir(parents=True, exist_ok=True)
    for idx in range(8):
        payload = "x" * (8_192 + idx * 128)
        (repo_dir / "data" / f"file_{idx:02d}.txt").write_text(payload, encoding="utf-8")

    run_cmd(["git", "-C", str(repo_dir), "add", "-A"])
    run_cmd(["git", "-C", str(repo_dir), "commit", "-m", "init benchmark repo"])
    return repo_dir


def make_agent_cmd(core_count: int, iterations: int) -> str:
    return (
        "set -euo pipefail\n"
        "python3 - <<'PY'\n"
        "import hashlib\n"
        "import multiprocessing as mp\n"
        "import pathlib\n"
        "import time\n"
        f"WORKERS = {core_count}\n"
        f"TOTAL_ITERS = {iterations}\n"
        "\n"
        "def worker(count: int) -> None:\n"
        "    block = b'x' * 1024\n"
        "    for _ in range(count):\n"
        "        hashlib.sha256(block).digest()\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    per_worker = max(1, TOTAL_ITERS // WORKERS)\n"
        "    started = time.perf_counter()\n"
        "    procs = [mp.Process(target=worker, args=(per_worker,)) for _ in range(WORKERS)]\n"
        "    for p in procs:\n"
        "        p.start()\n"
        "    for p in procs:\n"
        "        p.join()\n"
        "    elapsed = time.perf_counter() - started\n"
        "    pathlib.Path('BENCH_METRIC.json').write_text(\n"
        "        '{\\\"compute_seconds\\\": %.6f, \\\"workers\\\": %d}' % (elapsed, WORKERS),\n"
        "        encoding='utf-8',\n"
        "    )\n"
        "    print(f'BENCH_COMPUTE_SECONDS={elapsed:.6f}')\n"
        "PY\n"
        "echo done > BENCH_DONE\n"
    )


def write_spec(spec_path: pathlib.Path, image: str, core_count: int, iterations: int) -> None:
    spec = {
        "base_ref": "main",
        "image": image,
        "review": {"required_checks": ["test -f BENCH_DONE"]},
        "agents": [
            {
                "name": "cpu-burn",
                "cpus": str(core_count),
                "cmd": make_agent_cmd(core_count, iterations),
            }
        ],
    }
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")


def parse_compute_seconds(log_path: pathlib.Path) -> float | None:
    if not log_path.exists():
        return None
    text = log_path.read_text(encoding="utf-8", errors="replace")
    matches = re.findall(r"BENCH_COMPUTE_SECONDS=([0-9]+\.[0-9]+)", text)
    if not matches:
        return None
    return float(matches[-1])


def run_pipeline(
    binary: pathlib.Path,
    repo_dir: pathlib.Path,
    orch_dir: pathlib.Path,
    spec_path: pathlib.Path,
    run_id: str,
) -> dict[str, float | str | None]:
    env = os.environ.copy()
    env["NORMIES_ORCH_DIR"] = str(orch_dir)

    run_res = run_cmd(
        [
            str(binary),
            "run",
            "--repo",
            str(repo_dir),
            "--spec",
            str(spec_path),
            "--run-id",
            run_id,
        ],
        env=env,
    )
    review_res = run_cmd([str(binary), "review", "--run-id", run_id], env=env)
    integrate_res = run_cmd([str(binary), "integrate", "--run-id", run_id], env=env)
    cleanup_res = run_cmd([str(binary), "cleanup", "--run-id", run_id], env=env)

    log_path = orch_dir / "runs" / run_id / "agents" / "cpu-burn" / "docker.log"
    compute_seconds = parse_compute_seconds(log_path)

    return {
        "run_seconds": run_res.seconds,
        "review_seconds": review_res.seconds,
        "integrate_seconds": integrate_res.seconds,
        "cleanup_seconds": cleanup_res.seconds,
        "total_seconds": run_res.seconds
        + review_res.seconds
        + integrate_res.seconds
        + cleanup_res.seconds,
        "compute_seconds": compute_seconds,
    }


def parse_cores(raw: str, max_core: int) -> list[int]:
    if raw.strip().lower() == "all":
        return list(range(1, max_core + 1))
    cores: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part)
        if value < 1:
            raise ValueError("core counts must be >= 1")
        cores.append(value)
    unique = sorted(set(cores))
    if not unique:
        raise ValueError("no valid cores provided")
    return unique


def write_results(rows: list[dict[str, object]], csv_path: pathlib.Path, json_path: pathlib.Path) -> None:
    fieldnames = [
        "timestamp_utc",
        "core_count",
        "trial",
        "run_id",
        "run_seconds",
        "review_seconds",
        "integrate_seconds",
        "cleanup_seconds",
        "total_seconds",
        "compute_seconds",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark normies across core allocations")
    parser.add_argument(
        "--cores",
        default="all",
        help="Comma-separated core counts (e.g. 1,2,4,8) or 'all' for 1..logical cores",
    )
    parser.add_argument("--trials", type=int, default=2, help="Trials per core count")
    parser.add_argument(
        "--iterations",
        type=int,
        default=8_000_000,
        help="Total sha256 iterations per run (split across workers)",
    )
    parser.add_argument("--image", default="python:3.12-slim", help="Docker image for benchmark agent")
    parser.add_argument(
        "--output-prefix",
        default="benchmark_results",
        help="Prefix for CSV/JSON outputs in benchmark/results",
    )
    args = parser.parse_args()

    if args.trials < 1:
        raise ValueError("--trials must be >= 1")

    ensure_tools()
    max_core = os.cpu_count() or 1
    core_counts = parse_cores(args.cores, max_core)

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    binary = ensure_release_binary()
    ensure_docker_image(args.image)
    repo_dir = init_repo(ARTIFACTS_DIR / "workload_repo")

    # Fresh orchestrator state for this benchmark run.
    orch_dir = ARTIFACTS_DIR / "orchestrator"
    if orch_dir.exists():
        shutil.rmtree(orch_dir)
    orch_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    print(f"[run] cores={core_counts}, trials={args.trials}, iterations={args.iterations}")

    total_jobs = len(core_counts) * args.trials
    job_idx = 0
    for core in core_counts:
        for trial in range(1, args.trials + 1):
            job_idx += 1
            run_id = f"bench-c{core:02d}-t{trial:02d}-{int(time.time() * 1000) % 1_000_000:06d}-{random.randint(0, 9999):04d}"
            spec_path = ARTIFACTS_DIR / f"{run_id}.spec.json"
            write_spec(spec_path, args.image, core, args.iterations)
            print(f"[run {job_idx}/{total_jobs}] core={core} trial={trial} run_id={run_id}")

            timed = run_pipeline(binary, repo_dir, orch_dir, spec_path, run_id)
            row: dict[str, object] = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "core_count": core,
                "trial": trial,
                "run_id": run_id,
                **timed,
            }
            results.append(row)

            print(
                "  total={:.3f}s run={:.3f}s review={:.3f}s integrate={:.3f}s cleanup={:.3f}s compute={}".format(
                    float(row["total_seconds"]),
                    float(row["run_seconds"]),
                    float(row["review_seconds"]),
                    float(row["integrate_seconds"]),
                    float(row["cleanup_seconds"]),
                    "n/a"
                    if row["compute_seconds"] is None
                    else f"{float(row['compute_seconds']):.3f}s",
                )
            )

    csv_path = RESULTS_DIR / f"{args.output_prefix}.csv"
    json_path = RESULTS_DIR / f"{args.output_prefix}.json"
    write_results(results, csv_path, json_path)

    print(f"[done] wrote {csv_path}")
    print(f"[done] wrote {json_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
