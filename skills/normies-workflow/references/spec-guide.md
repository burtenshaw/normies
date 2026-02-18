# Normies Spec Guide

## Minimal JSON Spec

```json
{
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

1. `normies run --repo <repo> --spec <spec.json>`
2. `normies review --run-id <run_id>`
3. `normies integrate --run-id <run_id>`
4. `normies publish --run-id <run_id>`
5. Optional: `normies publish --run-id <run_id> --final-pr`
6. `normies cleanup --run-id <run_id>`

## Fast Spec Generation

Use the skill script:

```bash
./skills/normies-workflow/scripts/make_spec.py \
  --output /tmp/normies-spec.json \
  --repo owner/repo \
  --agent "lint::npm ci && npm run lint" \
  --agent "test::npm test" \
  --check "git diff --check"
```

Mark network-required agents:

```bash
./skills/normies-workflow/scripts/make_spec.py \
  --output /tmp/normies-spec.json \
  --repo owner/repo \
  --agent "deps::npm ci" \
  --agent "unit::npm test" \
  --network-agent deps
```

## Troubleshooting

- `docker daemon is not available`: start Docker before `normies run`.
- Agent status `failed`: inspect `normies logs --run-id <id> --agent <name>`.
- Agent status `blocked`: resolve uncommitted changes or set `auto_commit: true`.
- Review rejection: inspect `.orchestrator/runs/<run_id>/review/*.log`.
