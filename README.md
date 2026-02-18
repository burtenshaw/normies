# normies

`normies` is a Git-centric multi-agent orchestrator with mandatory Docker isolation.

- Agents run as independent Docker containers.
- Each agent gets its own Git branch and worktree.
- Review and integration happen locally.
- The orchestrator can publish one final branch and optionally open a final PR.

## Requirements

- `git`
- `docker` (daemon running and reachable)
- `uv`
- `gh` (optional, only for `publish --final-pr`)

## Quick Start

```bash
# one-time install (puts `normies` on your PATH via uv tool dir)
uv tool install -e .

# run directly as `normies`
normies run --repo <git-url-or-local-path> --spec examples/spec.yaml
normies status
normies review --run-id <run_id>
normies integrate --run-id <run_id>
normies publish --run-id <run_id>
# optional PR creation
normies publish --run-id <run_id> --final-pr
```

For local development without tool install:

```bash
uv run normies --help
```

`--repo` accepts:

- local repo path
- full git URL
- GitHub shorthand `owner/repo` (auto-resolved to `https://github.com/owner/repo.git`)

## Run Spec

YAML or JSON is supported.

```yaml
repo: https://github.com/owner/repo.git
base_ref: main
image: ubuntu:24.04

defaults:
  cpus: "2"
  memory: 4g
  pids_limit: 256
  needs_network: false
  auto_commit: true
  read_only_rootfs: false
  commit_prefix: agent

review:
  required_checks:
    - "git diff --check"

agents:
  - name: format-check
    base_ref: main
    cmd: |
      git status --short > /out/status.txt
      echo '{"status":"no_change","summary":"no code changes","checks":[],"artifacts":["status.txt"]}' > /out/result.json
    needs_network: false
    required_checks:
      - "git diff --check"

  - name: add-run-note
    cmd: |
      printf "\nRun: $RUN_ID\n" >> AGENT_RUN_NOTE.txt
      echo '{"status":"ok","summary":"added AGENT_RUN_NOTE.txt update","checks":[],"artifacts":[]}' > /out/result.json
```

Agent-level keys:

- `name` (required)
- `cmd` (required)
- `base_ref`, `image`, `env`
- `cpus`, `memory`, `pids_limit`
- `needs_network`, `read_only_rootfs`
- `auto_commit`, `commit_prefix`, `commit_message`
- `required_checks` (extra checks run during local review)

## Output Layout

`normies` stores run state under `.orchestrator/`:

```text
.orchestrator/
  repos/<repo>.git/                 # local bare git hub
  runs/<run_id>/
    run.json                        # canonical run manifest
    agents/<agent_name>/
      worktree/
      out/result.json
      docker.log
    review/review.json
    integration/integration.json
```

## Command Reference

- `run`: execute all agents in Docker and persist run metadata.
- `status`: show one run (`--run-id`) or list all runs.
- `logs`: print one agent's Docker log file.
- `review`: run local required checks and produce acceptance results.
- `integrate`: rebase accepted branches onto integration branch, then ff-merge.
- `publish`: push final branch; optional `--final-pr` uses `gh pr create`.
- `cleanup`: remove worktrees; optional `--remove-run-dir`.

## Notes

- Docker execution is mandatory for agents.
- If an agent modifies files but creates no commit, orchestrator auto-commit is enabled by default.
- If `auto_commit` is disabled and uncommitted changes remain, the agent is marked `blocked`.
- Local review gates integration; GitHub/PR is only final publication when requested.
- Project dependencies and lockfile are managed by `uv` (`pyproject.toml` + `uv.lock`).

## Testing

```bash
uv run --group dev pytest -q
```
