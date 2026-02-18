# Benchmark Harness

Scripts:

- `benchmark/scripts/run_benchmark.py`: runs `normies run/review/integrate/cleanup` experiments across core allocations and records timings.
- `benchmark/scripts/plot_profiles.py`: generates profiling plots and summary statistics from benchmark CSV output.

Outputs:

- `benchmark/results/benchmark_results.csv`
- `benchmark/results/benchmark_results.json`
- `benchmark/results/summary.json`
- `benchmark/plots/*.png`

Example:

```bash
python3 benchmark/scripts/run_benchmark.py --cores all --trials 2 --iterations 8000000
uv run --with matplotlib python benchmark/scripts/plot_profiles.py
```
