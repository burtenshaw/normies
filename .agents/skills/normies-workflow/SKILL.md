---
name: normies-workflow
description: Orchestrate Docker-isolated, branch-based multi-agent git workflows with normies. Use for parallel edits, retries, and explicit review/integration gates.
---

<!-- normies:init:start -->
# Normies Workflow

## When To Use

Use this skill when work should be parallelized across multiple agents or needs branch-isolated execution with review gates.

## Run Sequence

1. `normies doctor --repo <repo>`
2. `normies init --template baseline --output normies.spec.json --repo <repo> --yes`
3. `normies run --repo <repo> --spec normies.spec.json --jobs <N>`
4. `normies retry --run-id <run_id> --failed --jobs <N>` (if needed)
5. `normies review --run-id <run_id>`
6. `normies integrate --run-id <run_id>`
7. `normies cleanup --run-id <run_id>`

## Default Guardrails

- Keep `needs_network` disabled unless required.
- Keep commands idempotent and non-interactive.
- Keep `review.required_checks` explicit.
<!-- normies:init:end -->
