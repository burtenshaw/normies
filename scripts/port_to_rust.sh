#!/usr/bin/env bash
set -euo pipefail

cp .port/Cargo.toml Cargo.toml
mkdir -p src tests
cp .port/src/lib.rs src/lib.rs
cp .port/src/main.rs src/main.rs
cp .port/tests/cli.rs tests/cli.rs
cp .port/README.md README.md
cp .port/.gitignore .gitignore

mkdir -p skills/normies-workflow/agents skills/normies-workflow/references
cp .port/skills/normies-workflow/SKILL.md skills/normies-workflow/SKILL.md
cp .port/skills/normies-workflow/agents/openai.yaml skills/normies-workflow/agents/openai.yaml
cp .port/skills/normies-workflow/references/spec-guide.md skills/normies-workflow/references/spec-guide.md

rm -f normies.py pyproject.toml uv.lock
rm -f tests/test_normies.py
rm -f skills/normies-workflow/scripts/make_spec.py
rm -rf __pycache__ .pytest_cache .venv

rm -rf .port scripts/port_to_rust.sh
