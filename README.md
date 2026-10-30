# Security remediation (supervised local prototype)

The `src/` Python CLI described next is the earlier uv-only pilot, superseded by `remediate.py` (see "Current pipeline" below). It is kept, not deleted.

A Python CLI for one saved dependency alert in a clean Git checkout. It first tries a deterministic compatible uv upgrade; if that fails, it may invoke one preconfigured **pi** coding agent (at most three reserved CLI invocations across restarts). Runner-owned code validates a candidate and independently checks a fresh selected environment. It emits a local patch/report only, **never** publishes a PR, merges code, or dismisses alerts.

## Requirements and quick start

macOS/Linux with `uv 0.12.12`, `pi 0.99.1`, Git, and a uv-managed CPython `3.12.14`. The disposable fixture uses public PyPI and a live `pip-audit` advisory feed. Install the interpreter and runner dependencies:

```sh
uv python install 3.12.14
uv sync --python 3.12.14 --locked --no-build
uv run --locked pytest
uv run --locked ruff check src tests skills
```

Network-free simulation (not verified security evidence):

```sh
uv run --locked security-remediation fixture --fixture tests/fixtures/pilot --output /tmp/remediation-fixture-out --case direct
# Other cases: forbidden, scanner-error, baseline-failure
# Read /tmp/remediation-fixture-out/fixture-result.json: simulated=true, verified=false.
```

To run the real disposable pilot, first make a **separate clean Git checkout** from the fixture files. Do not point `--source` at this development repo or reuse a modified source:

```sh
tmp=$(mktemp -d /tmp/remediation-pilot.XXXXXX)
cp -R tests/fixtures/pilot "$tmp/source"
git -C "$tmp/source" init -q
git -C "$tmp/source" add .
git -C "$tmp/source" -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm baseline
uv run --locked security-remediation run \
  --alert-file tests/fixtures/alerts/urllib3.json \
  --source "$tmp/source" \
  --policy config/pilot-policy.example.yaml \
  --state-dir "$tmp/state" --output "$tmp/out"
git -C "$tmp/source" apply --check "$tmp/out/candidate.patch"
```

Read `$tmp/out/{candidate.patch,assessment.json,plan.json,verification.json,run-result.json,report.md}`. A re-run with the **same** source, alert, policy, and state directory resumes the same operation and re-verifies a retained candidate. Keep state and output outside `--source`. The original checkout is never edited. State includes a base snapshot, candidate and durable attempt ledger, but is **local to this machine**: deletion/machine loss needs separate backup/persistence. A changed base, alert, policy, or skill conflicts rather than silently resetting attempts. A human can start a distinct operation while retaining the old history using `--operation-id operator-retry-1 --new-operation-reason 'reason'` and a fresh output directory; use this deliberately, not as an automatic retry mechanism.

Exit codes: `0` verified local candidate, `10` blocked, `20` attempt budget exhausted, `30` operational error, `40` state/source conflict (invalid or ineligible input is `10`). Fixture command exit 0 means **only that the simulated fixture ran**. Invalid input/conflict can exit before a result file is created; normal blocked/operational paths write `run-result.json`.

## Current pipeline: triage, remediate.py, escalation skill

Dependency remediation is high-certainty, so a deterministic tool does it; the agent only handles escalations.

1. **Triage** (`skills/security-triage/`): ranks open Dependabot alerts and [security-audit-skill](https://github.com/cloudflare/security-audit-skill) `findings.json` into one read-only worklist (stdlib `python3`).
2. **`skills/vulnerability-remediation/remediate.py`**: baseline check and scan, new branch, ecosystem fix, scope check, verify (`scan_diff.py`), commit. Stdlib only, needs `osv-scanner` and the repo toolchain.
   ```sh
   python3 skills/vulnerability-remediation/remediate.py fix --package urllib3 --advisory GHSA-xxxx-xxxx-xxxx \
     --version 2.8.0 --check "uv sync --locked && uv run pytest" --out ../remediation
   ```
   Exit `0` fixed and committed; `1` escalate (reason in `result.json`); `2` cannot start. Automated: npm and Maven (via experimental `osv-scanner fix`), Go, Cargo, uv (native commands). Gradle, Poetry, pip-tools, Bundler, NuGet, pnpm and Yarn are manual.
3. **Escalation skill** (`skills/vulnerability-remediation/SKILL.md`): for exit 1 and for unautomated ecosystems; the agent reads `result.json` and logs, acts per reason, then runs `remediate.py verify`. Harness-neutral:
   ```sh
   ln -s "$PWD/skills/vulnerability-remediation" /path/to/repo/.github/skills/vulnerability-remediation   # Copilot
   ln -s "$PWD/skills/vulnerability-remediation" /path/to/repo/.claude/skills/vulnerability-remediation   # Claude Code
   ```
4. **Example workflow** `skills/vulnerability-remediation/examples/remediate.yml`: `workflow_dispatch` that runs `fix`, opens a PR on success, and uploads evidence. Test plan: [docs/remediation-test-plan.md](docs/remediation-test-plan.md).

## What is checked and what is not

- Pilot: Python 3.12.14, public PyPI wheels, default runtime dependencies only (no extras/groups or third-party VCS/path sources). The runner and pilot each have their own `uv.lock`; include both when committing this work. Pilot has a real `unittest` suite; `tests` collection must be nonempty and not shrink. Optional lint/build can be configured as trusted absolute commands, but the pilot has neither. This is **not** a general Python dependency solver; transitive parent migrations and major upgrades are blocked/manual.
- Baseline and candidate: `uv lock --check`, wheel-only `uv sync --locked --no-install-project`, `uv pip check`, exact installed-vs-lock inventory, tests, and `pip-audit --path` for the selected site-packages. The scanner is installed in the separate runner environment; it does **not** read `uv.lock` directly. Require a mapped target at baseline, a version outside its affected range, no target alias at candidate, complete audit coverage, and no new reported advisory/package identities. Unchanged unrelated findings are disclosed, not silently suppressed. Audit evidence is time-specific, not a proof of complete security.
- Diff validation rejects edits to tests, CI, settings, tool configurations, unapproved TOML sections, new files/symlinks, executables, downgrades, unexpected sources, prereleases, and oversized changes. A source-adaptation path exists via pi, but only the deterministic direct-update path and pi headless smoke were exercised live. Tests use a fake agent and scanner; they do not incur model charges.
- **No sandbox is provided.** Running pi, package installation, or project tests on the host is appropriate only for this supervised synthetic pilot. A package or agent tool may access host credentials and runner state. Path filters, project trust, and process-group killing are not a security boundary. No unattended or production-source runs until worker isolation and credential separation are proven. See [compatibility and limitations](docs/harness-compatibility.md).

Observed live pilot on 2026-10-01: baseline urllib3 2.0.6 with 9 reported findings; deterministic candidate urllib3 2.8.0 with 0; baseline and candidate lock/sync/inventory/tests/audit passed, zero pi attempts, candidate patch passed `git apply --check`. Future advisory feeds may yield different results or a blocked run.

Current decisions: [phased plan](docs/phased-plan.md), [as-built design](docs/current-design.md), and [current proposal](docs/current-proposal.md). The original root-level proposal, design and brief documents have been deleted.
