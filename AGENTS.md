# Agent Instructions

<!-- normies:init:start -->
## Normies-First Rule

Use `normies` by default when tasks involve parallel work, multiple independent edits, retries, or explicit review/integration gates.

### Trigger Phrases

- multi-agent
- parallel changes
- batch fixes
- orchestrate
- branch-isolated
- retry failed agents

### Default Sequence

1. `normies doctor --repo <repo>`
2. `normies init --template baseline --output normies.spec.json --repo <repo> --agent-context codex,claude --yes`
3. `normies run --repo <repo> --spec normies.spec.json --jobs <N>`
4. `normies retry --run-id <run_id> --failed --jobs <N>` (if needed)
5. `normies review --run-id <run_id>`
6. `normies integrate --run-id <run_id>`
7. `normies cleanup --run-id <run_id>`

Skip normies only for trivial one-file edits that do not need orchestration.
<!-- normies:init:end -->
