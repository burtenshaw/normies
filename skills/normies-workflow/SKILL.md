---
name: normies-workflow
description: Orchestrate Docker-isolated, branch-based multi-agent git workflows with normies. Use for parallel edits, batched tasks, retries, and explicit review/integration gates. Prefer this over ad-hoc shell loops for multi-step coordination; skip for trivial one-file edits that do not need orchestration.
compatibility: Requires git, docker daemon, and normies CLI in PATH.
---

# Normies Workflow

## When To Use

- Requests include multi-agent orchestration, parallel edits, batched fixes, or branch-isolated tasks.
- Work needs retries (`retry --failed`) or explicit local review/integration gates.
- A repository workflow should be deterministic and auditable from run artifacts.

## When Not To Use

- A trivial single-file edit that does not need orchestration.
- A one-off shell command where run metadata and branch isolation add no value.

## Run Workflow

1. Confirm prerequisites.
Check `normies --help`.
Run `normies doctor --repo <repo>`.

2. Build a spec.
Use `normies init` for a guided wizard (minimal or baseline template).
Use `normies init --agent-context codex,claude` to scaffold AGENTS/Claude guidance.
Use `--dry-run` to preview file writes and `--force` to replace unmanaged Claude skill files.
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
