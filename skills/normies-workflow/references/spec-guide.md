# Normies Spec Guide

## Minimal JSON Spec

```json
{
  "schema_version": 1,
  "repo": "owner/repo",
  "base_ref": "main",
  "image": "ubuntu:24.04",
  "agents": [
    {
      "name": "lint",
      "cmd": "npm ci && npm run lint"
    }
  ]
}
```

## Recommended Baseline

```json
{
  "schema_version": 1,
  "repo": "owner/repo",
  "base_ref": "main",
  "image": "ubuntu:24.04",
  "defaults": {
    "cpus": "2",
    "memory": "4g",
    "pids_limit": 256,
    "needs_network": false,
    "auto_commit": true,
    "read_only_rootfs": false,
    "commit_prefix": "agent"
  },
  "review": {
    "required_checks": ["git diff --check"]
  },
  "agents": [
    {
      "name": "lint",
      "cmd": "npm ci && npm run lint"
    },
    {
      "name": "test",
      "cmd": "npm test"
    }
  ]
}
```

## Agent Keys

- Required: `name`, `cmd`
- Optional: `base_ref`, `image`, `env`
- Optional runtime: `cpus`, `memory`, `pids_limit`, `needs_network`, `read_only_rootfs`
- Optional commit behavior: `auto_commit`, `commit_prefix`, `commit_message`
- Optional review: `required_checks`

## Command Sequence

1. `normies doctor --repo <repo>`
2. `normies run --repo <repo> --spec <spec.json> --jobs <N>`
3. Optional retry for failed agents: `normies retry --run-id <run_id> --failed --jobs <N>`
4. `normies review --latest` (or `--run-id <run_id>`)
5. `normies integrate --latest` (or `--run-id <run_id>`)
   - Integration writes `.orchestrator/runs/<run_id>/integration/codex-handoff.md`
   - `--json` includes `codex.fetch_integration_branch` and `codex.merge_fetched_branch`
6. Push manually using integrate output:
   `git --git-dir <hub_path> push origin <integration_branch>`
7. `normies cleanup --latest` (or `--run-id <run_id>`)

## Fast Spec Generation

Use `normies make-spec`:

```bash
normies make-spec \
  --output /tmp/normies-spec.json \
  --repo owner/repo \
  --agent "lint::npm ci && npm run lint" \
  --agent "test::npm test" \
  --check "git diff --check"
```

Disable auto-commit in generated specs:

```bash
normies make-spec \
  --output /tmp/normies-spec.json \
  --agent "lint::npm ci && npm run lint" \
  --no-auto-commit
```

Mark network-required agents:

```bash
normies make-spec \
  --output /tmp/normies-spec.json \
  --repo owner/repo \
  --agent "deps::npm ci" \
  --agent "unit::npm test" \
  --network-agent deps
```

## Troubleshooting

- `docker daemon is not available`: start Docker before `normies run`.
- Agent status `failed`: inspect `normies logs --latest --list-agents` then
  `normies logs --latest --agent <name> --tail 200`.
- Agent status `blocked`: resolve uncommitted changes or set `auto_commit: true`.
- Review rejection: inspect `.orchestrator/runs/<run_id>/review/*.log`.
- No run id supplied: commands like `review`, `integrate`, `logs`, and `cleanup`
  default to the latest run. Use `--run-id` for an explicit run.
- Worktree visibility: use `normies status --run-id <run_id> --json` to inspect
  `worktree_status` for each agent and integration worktree.
