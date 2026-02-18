# normies

`normies` is a git-centric multi-agent orchestrator with mandatory Docker isolation.

- Agents run as independent Docker containers.
- Each agent uses an isolated git branch and worktree.
- Review and integration happen locally.
- Final publishing can push a branch and optionally open a PR.

## Requirements

- `git`
- `docker` (daemon running and reachable)
- `rustup` / `cargo` (Rust 1.93+)
- `gh` (optional, only for `publish --final-pr`)

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
normies run --repo <git-url-or-local-path> --spec examples/spec.yaml
normies status
normies review --run-id <run_id>
normies integrate --run-id <run_id>
normies publish --run-id <run_id>
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

## Testing

```bash
cargo test
```
