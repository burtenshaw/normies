---
name: normies-workflow
description: Run the `normies` CLI to orchestrate Docker-isolated multi-agent git workflows with local review/integration. Use when an agent needs to create or edit `normies` run specs, execute `normies doctor/init/make-spec/run/retry/review/integrate/logs/cleanup`, troubleshoot failed or blocked runs, or coordinate multiple branch-isolated commands against one repository.
---

# Normies Workflow

## Overview

Use this skill to execute reliable `normies` runs end to end.
Prefer this workflow when coordinating multiple agent commands with strict Docker isolation and local git-first review.

## Run Workflow

1. Confirm prerequisites.
Check `normies --help`.
Run `normies doctor --repo <repo>`.

2. Build a spec.
Use `normies init` for a guided wizard (minimal or baseline template).
Use `normies make-spec` for fast, valid JSON specs.
Read `references/spec-guide.md` for full field details and patterns.

3. Execute the pipeline.
Run `normies run --repo <repo> --spec <spec> --jobs <N>`.
Run `normies retry --run-id <run_id> --failed --jobs <N>` if any agents failed.
Run `normies review --latest` (or `--run-id <run_id>`).
Run `normies integrate --latest` (or `--run-id <run_id>`).
Use the printed push command from integrate output to push manually.

4. Triage failures.
Run `normies status --latest`.
Run `normies logs --latest --list-agents`.
Run `normies logs --latest --agent <agent_name> --tail 200`.
Run `normies logs --latest --agent <agent_name> --follow` for live logs.
Inspect `.orchestrator/runs/<run_id>/run.json` for full per-agent state.

5. Clean up worktrees after completion.
Run `normies cleanup --latest`.
Add `--remove-run-dir` when you also want to remove run metadata and artifacts.

## Execution Defaults

- Keep `needs_network` disabled unless the task requires network.
- Keep `auto_commit` enabled unless explicit manual commit behavior is needed.
- Keep per-agent commands idempotent and non-interactive.
- Keep review checks explicit in `review.required_checks`.
- Use `--json` when output is consumed by scripts/automation.

## Status Interpretation

- Treat `failed` as execution failure (container/command failed).
- Treat `blocked` as unresolved workflow state (for example dirty worktree with `auto_commit: false`).
- Treat `no_change` as valid no-op.
- Treat `ok` as successful output ready for review/integration.

## Resources

- `references/spec-guide.md`: Review spec schema, command sequence, and troubleshooting tips.
