# Project agent memory

security-remediation: this file is the always-loaded memory for agents working in this repo.
It is kept short on purpose - every line here is paid on every session.

## Learnings

- Current direction: deterministic `skills/vulnerability-remediation/remediate.py` (osv-scanner + native tools) with an agent skill for escalations; the `src/` CLI is the earlier uv-only pilot. Local-only, no GitHub publisher or Jenkins integration; `README.md` has commands; `docs/phased-plan.md`, `docs/current-design.md`, `docs/current-proposal.md` reflect decisions.
- Run `uv run --locked pytest` and `uv run --locked ruff check src tests skills`. The CLI and pilot have separate `pyproject.toml`/`uv.lock` pairs; pilot inputs live under `tests/fixtures/`.
- A live disposable pilot upgraded urllib3 2.0.6 to 2.8.0 with 12 passing baseline/candidate checks and zero pi calls (2026-10-01). Pi's headless skill invocation was smoke-tested, **not** a live agent-authored repair. Audit findings can change with the feed.
- No sandbox or credential separation has been proven: pi, installs, and tests run on the host. Do not claim unattended/production safety or enable publication on this evidence; see `docs/harness-compatibility.md`.
- Keep state, output, and trusted policy outside the clean source checkout. Attempt reservations persist only while local state survives; changing base/alert/policy/skill conflicts rather than silently resetting the budget.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
