#!/usr/bin/env python3
"""Generate profiling plots from benchmark CSV results."""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import statistics
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "benchmark"
DEFAULT_RESULTS = BENCH_DIR / "results" / "benchmark_results.csv"
DEFAULT_PLOTS = BENCH_DIR / "plots"
DEFAULT_SUMMARY = BENCH_DIR / "results" / "summary.json"


def read_rows(csv_path: pathlib.Path) -> list[dict[str, float | int | str | None]]:
    rows: list[dict[str, float | int | str | None]] = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            rows.append(
                {
                    "timestamp_utc": raw["timestamp_utc"],
                    "core_count": int(raw["core_count"]),
                    "trial": int(raw["trial"]),
                    "run_id": raw["run_id"],
                    "run_seconds": float(raw["run_seconds"]),
                    "review_seconds": float(raw["review_seconds"]),
                    "integrate_seconds": float(raw["integrate_seconds"]),
                    "cleanup_seconds": float(raw["cleanup_seconds"]),
                    "total_seconds": float(raw["total_seconds"]),
                    "compute_seconds": None
                    if raw["compute_seconds"] in ("", "None")
                    else float(raw["compute_seconds"]),
                }
            )
    if not rows:
        raise RuntimeError(f"no rows found in {csv_path}")
    return rows


def summarize(rows: list[dict[str, float | int | str | None]]) -> dict[str, object]:
    by_core: dict[int, list[dict[str, float | int | str | None]]] = defaultdict(list)
    for row in rows:
        by_core[int(row["core_count"])].append(row)

    summary_rows = []
    for core in sorted(by_core):
        group = by_core[core]

        total = [float(r["total_seconds"]) for r in group]
        run = [float(r["run_seconds"]) for r in group]
        review = [float(r["review_seconds"]) for r in group]
        integrate = [float(r["integrate_seconds"]) for r in group]
        cleanup = [float(r["cleanup_seconds"]) for r in group]
        compute = [float(r["compute_seconds"]) for r in group if r["compute_seconds"] is not None]

        item = {
            "core_count": core,
            "trials": len(group),
            "total_mean": statistics.fmean(total),
            "total_std": statistics.stdev(total) if len(total) > 1 else 0.0,
            "run_mean": statistics.fmean(run),
            "review_mean": statistics.fmean(review),
            "integrate_mean": statistics.fmean(integrate),
            "cleanup_mean": statistics.fmean(cleanup),
            "compute_mean": statistics.fmean(compute) if compute else None,
            "compute_std": statistics.stdev(compute) if len(compute) > 1 else 0.0,
        }
        summary_rows.append(item)

    base_total = next(x["total_mean"] for x in summary_rows if x["core_count"] == 1)
    for row in summary_rows:
        row["total_speedup_vs_1_core"] = base_total / row["total_mean"]

    return {
        "num_rows": len(rows),
        "cores": [r["core_count"] for r in summary_rows],
        "summary_by_core": summary_rows,
    }


def plot_total_runtime(summary_rows: list[dict[str, object]], out_path: pathlib.Path) -> None:
    cores = [int(r["core_count"]) for r in summary_rows]
    means = [float(r["total_mean"]) for r in summary_rows]
    stds = [float(r["total_std"]) for r in summary_rows]

    plt.figure(figsize=(10, 5))
    plt.errorbar(cores, means, yerr=stds, marker="o", linewidth=2, capsize=4, color="#1f77b4")
    plt.title("Normies End-to-End Runtime vs Core Allocation")
    plt.xlabel("Agent CPU cores (--cpus)")
    plt.ylabel("Total pipeline seconds (run+review+integrate+cleanup)")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def plot_stage_profile(summary_rows: list[dict[str, object]], out_path: pathlib.Path) -> None:
    cores = [int(r["core_count"]) for r in summary_rows]
    run = [float(r["run_mean"]) for r in summary_rows]
    review = [float(r["review_mean"]) for r in summary_rows]
    integrate = [float(r["integrate_mean"]) for r in summary_rows]
    cleanup = [float(r["cleanup_mean"]) for r in summary_rows]

    plt.figure(figsize=(12, 6))
    plt.bar(cores, run, label="run", color="#4c78a8")
    plt.bar(cores, review, bottom=run, label="review", color="#f58518")
    bottom_integrate = [a + b for a, b in zip(run, review)]
    plt.bar(cores, integrate, bottom=bottom_integrate, label="integrate", color="#54a24b")
    bottom_cleanup = [a + b + c for a, b, c in zip(run, review, integrate)]
    plt.bar(cores, cleanup, bottom=bottom_cleanup, label="cleanup", color="#e45756")

    plt.title("Normies Stage Profiling by Core Allocation")
    plt.xlabel("Agent CPU cores (--cpus)")
    plt.ylabel("Mean stage time (seconds)")
    plt.legend()
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def plot_compute_and_speedup(summary_rows: list[dict[str, object]], out_path: pathlib.Path) -> None:
    cores = [int(r["core_count"]) for r in summary_rows]
    compute = [float(r["compute_mean"] or 0.0) for r in summary_rows]
    speedup = [float(r["total_speedup_vs_1_core"]) for r in summary_rows]

    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax1.plot(cores, compute, marker="o", color="#2ca02c", linewidth=2, label="compute seconds")
    ax1.set_xlabel("Agent CPU cores (--cpus)")
    ax1.set_ylabel("In-container compute seconds", color="#2ca02c")
    ax1.tick_params(axis="y", labelcolor="#2ca02c")
    ax1.grid(alpha=0.25)

    ax2 = ax1.twinx()
    ax2.plot(cores, speedup, marker="s", color="#d62728", linewidth=2, label="speedup")
    ax2.set_ylabel("Total speedup vs 1 core", color="#d62728")
    ax2.tick_params(axis="y", labelcolor="#d62728")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="best")
    plt.title("Compute Time and End-to-End Speedup")
    fig.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot normies benchmark results")
    parser.add_argument("--input", type=pathlib.Path, default=DEFAULT_RESULTS)
    parser.add_argument("--plots-dir", type=pathlib.Path, default=DEFAULT_PLOTS)
    parser.add_argument("--summary", type=pathlib.Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()

    rows = read_rows(args.input)
    summary = summarize(rows)
    summary_rows = summary["summary_by_core"]

    args.plots_dir.mkdir(parents=True, exist_ok=True)
    plot_total_runtime(summary_rows, args.plots_dir / "total_runtime_vs_core.png")
    plot_stage_profile(summary_rows, args.plots_dir / "stage_profile_by_core.png")
    plot_compute_and_speedup(summary_rows, args.plots_dir / "compute_and_speedup.png")

    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(f"wrote plots to {args.plots_dir}")
    print(f"wrote summary to {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
