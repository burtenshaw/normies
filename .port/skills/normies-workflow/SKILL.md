---
name: normies-workflow
description: Run the `normies` CLI to orchestrate Docker-isolated multi-agent git workflows with local review/integration and optional final PR publication. Use when an agent needs to create or edit `normies` run specs, execute `normies run/review/integrate/publish/cleanup`, troubleshoot failed or blocked runs, or coordinate multiple branch-isolated commands against one repository.
---

# Normies Workflow

## Overview

Use this skill to execute reliable `normies` runs end to end.
Prefer this workflow when coordinating multiple agent commands with strict Docker isolation and local git-first review.

## Run Workflow

1. Confirm prerequisites.
Check `normies --help`.
Check `docker info`.

2. Build a spec.
Use `normies make-spec` for fast, valid JSON specs.
Read `references/spec-guide.md` for full field details and patterns.

3. Execute the pipeline.
Run `normies run --repo <repo> --spec <spec>`.
Run `normies review --run-id <run_id>`.
Run `normies integrate --run-id <run_id>`.
Run `normies publish --run-id <run_id>` and add `--final-pr` only when remote PR creation is required.

4. Triage failures.
Run `normies status --run-id <run_id>`.
Run `normies logs --run-id <run_id> --agent <agent_name>`.
Inspect `.orchestrator/runs/<run_id>/run.json` for full per-agent state.

5. Clean up worktrees after completion.
Run `normies cleanup --run-id <run_id>`.
Add `--remove-run-dir` when you also want to remove run metadata and artifacts.

## Execution Defaults

- Keep `needs_network` disabled unless the task requires network.
- Keep `auto_commit` enabled unless explicit manual commit behavior is needed.
- Keep per-agent commands idempotent and non-interactive.
- Keep review checks explicit in `review.required_checks`.

## Status Interpretation

- Treat `failed` as execution failure (container/command failed).
- Treat `blocked` as unresolved workflow state (for example dirty worktree with `auto_commit: false`).
- Treat `no_change` as valid no-op.
- Treat `ok` as successful output ready for review/integration.

## Resources

- `references/spec-guide.md`: Review spec schema, command sequence, and troubleshooting tips.
