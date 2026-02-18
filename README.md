# normies

`normies` is a git-centric multi-agent orchestrator with mandatory Docker isolation.

- Agents run as independent Docker containers.
- Each agent uses an isolated git branch and worktree.
- Review and integration happen locally.
- You can push integrated branches yourself and open PRs from your normal git workflow.
- Human-readable output is default; use `--json` for machine output.

## Requirements

- `git`
- `docker` (daemon running and reachable)
- `rustup` / `cargo` (Rust 1.93+)

## Build

```bash
cargo build
```

Run directly:

```bash
cargo run -- run --repo <git-url-or-local-path> --spec examples/spec.yaml
```

Install globally:

```bash
cargo install --path .
normies --help
```

## Quick Start

```bash
normies doctor --repo <git-url-or-local-path>
normies run --repo <git-url-or-local-path> --spec examples/spec.yaml --jobs 2
normies status
normies review --latest
normies integrate --latest
```

Push the integrated branch when you are ready:

```bash
# get hub_path + integration_branch
normies status --run-id <run_id>

# then push that branch yourself
git --git-dir <hub_path> push origin <integration_branch>
```

Codex-friendly merge handoff is written during integration:

```bash
normies integrate --run-id <run_id> --json
# inspect codex.handoff_markdown_path and codex.fetch_integration_branch
```

Status JSON now includes worktree transparency metadata:

```bash
normies status --run-id <run_id> --json
# includes run_dir, manifest_path, and worktree_status for integration + agents
```

Retry only failed agents:

```bash
normies retry --run-id <run_id> --failed --jobs 2
```

Inspect logs:

```bash
normies logs --latest --list-agents
normies logs --latest --agent <agent_name> --tail 200
normies logs --latest --agent <agent_name> --follow
```

## Host A2A Gateway (Opt-in)

Enable per-run local A2A proxying with a Unix socket gateway:

```yaml
a2a_gateway:
  enabled: true

agents:
  - name: planner
    cmd: ./run-agent.sh
    a2a:
      serve: true
      description: planning agent
```

When enabled, each agent receives:

- `NORMIES_A2A_GATEWAY_SOCKET=/gateway/gateway.sock`
- `NORMIES_A2A_GATEWAY_BASE_URL=http://a2a.local`
- `NORMIES_A2A_AGENT_ID=<agent_name>`
- `NORMIES_A2A_AGENT_SOCKET=/gateway/agents/<agent_name>.sock`
- `NORMIES_A2A_TOKEN=<per-agent bearer token>`
- `NORMIES_A2A_PEERS_JSON=<json peer map>`

Gateway metadata is included in `run --json` and `status --json` under `gateway`.

Useful OS tools:

```bash
# send request over UDS
curl --unix-socket "$NORMIES_A2A_GATEWAY_SOCKET" \
  -H "Authorization: Bearer $NORMIES_A2A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"ping"}' \
  "$NORMIES_A2A_GATEWAY_BASE_URL/v1/agents/<peer>/message:send"

# stream events over UDS
curl -N --unix-socket "$NORMIES_A2A_GATEWAY_SOCKET" \
  -H "Authorization: Bearer $NORMIES_A2A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"stream"}' \
  "$NORMIES_A2A_GATEWAY_BASE_URL/v1/agents/<peer>/message:stream"

# inspect sockets/logs
lsof -U | rg gateway.sock
ss -xl | rg gateway.sock
tail -f .orchestrator/runs/<run_id>/gateway/gateway.log

# debug UDS via local TCP bridge
socat TCP-LISTEN:7777,reuseaddr,fork UNIX-CONNECT:"$NORMIES_A2A_GATEWAY_SOCKET"
```

Generate a JSON spec:

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

Initialize a spec with the wizard:

```bash
normies init
```

Non-interactive init:

```bash
normies init --yes --template baseline --output normies.spec.json --repo owner/repo
```

Scaffold agent guidance for Codex + Claude while initializing:

```bash
normies init \
  --yes \
  --template baseline \
  --output normies.spec.json \
  --repo . \
  --agent-context codex,claude
```

Preview generated files without writing:

```bash
normies init --yes --output normies.spec.json --agent-context codex --dry-run
```

Replace an existing unmanaged Claude skill file:

```bash
normies init --yes --output normies.spec.json --agent-context claude --force
```

## Testing

```bash
cargo test
```

## Quality Gate

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Or use aliases:

```bash
cargo qa
cargo ci
```
