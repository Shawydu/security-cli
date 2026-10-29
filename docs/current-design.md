# Current technical design — implemented local pilot

Status: **as built, 2026-10-01**. This describes the actual narrow CLI and its known gaps, not the aspirational isolation/publication design in [the original specification](../Security_Remediation_Design.md). [Roadmap](phased-plan.md) and [proposal](current-proposal.md) distinguish next work from implemented behavior. Use [README](../README.md) for executable commands.

## Authority and flow

```text
saved alert + trusted policy + clean Git checkout
      ↓
runner: validate input; lock local operation; export base; verify baseline
      ↓
uv compatible target upgrade (zero pi calls)
      └─ if unsuccessful: reserve one durable pi invocation, then accept only permitted edits
      ↓
validate whole diff and lock; snapshot candidate + digest + patch checkpoint
      ↓
runner: fresh selected-environment checks on base and candidate
      ↓
local candidate.patch + assessment/plan + verification.json + report.md + run-result.json
```

- `src/security_remediation/cli.py` offers `run` and an **offline simulated** `fixture` command, not a `--publish` flag. Exit 0 = locally verified; 10 = blocked/ineligible; 20 = exhausted; 30 = operational failure; 40 = state/source conflict. Early input/conflict failures need not write `run-result.json`.
- `src/security_remediation/runner.py` owns policy/input checks, base export, state transitions, candidate checkpoint and local report. `src/security_remediation/harness.py` calls one preconfigured pi CLI (no model routing or direct SDK); `skills/vulnerability-remediation/SKILL.md` supplies procedure, never permission to bypass runner policy. Deterministic fixes supply simple assessment/plan text without pi.
- `src/security_remediation/state.py` uses Unix `flock`, revision checks, atomic state files and an event log under an operator-provided state directory. Operation ID derives from repository + alert number + optional explicit local ID. Base commit, raw alert/policy digests and skill digest must match on restart. Reserve before invoking pi (max 3 invocations including failed/interrupted ones); resume a complete candidate only after digest/patch validation and **re-verification**. An operator may supply a new ID and reason to retain previous history; losing all local state loses the retry ledger. No cross-machine durability.
- `src/security_remediation/workspace.py` exports the **clean Git HEAD** into a separate base and hashes file bytes in the candidate snapshot. It rejects untracked/new/deleted/symlink/executable/binary changes, forbidden paths including tests/CI/config, non-dependency TOML edits, downgrades, major/0.x-minor changes, unsupported package sources, and oversized edits. The source checkout is not edited. A digest is an integrity check against observed changes, **not** a malicious-process isolation boundary.

## Exact pilot and verification contract

- Supported selection: public PyPI, wheel-only third-party packages, Python **3.12.14** on the selected host, default runtime dependencies only. `config/pilot-policy.example.yaml` fixes repository, checks and limits; `src/security_remediation/runner.py:load` explicitly rejects configured extras/groups. The runner and `tests/fixtures/pilot/` have separate `pyproject.toml`/`uv.lock` pairs; no private index, VCS/path third-party dependencies, broad transitive-parent migration, or major-version fixes.
- `src/security_remediation/dependencies.py` first asks pinned uv **0.12.12** to upgrade the direct affected package within its existing constraint. If that cannot make a candidate, pi may edit approved dependency fields/source; the runner regenerates `uv.lock`. Pi must not hand-edit that lock. Candidate resolved-version changes and approved sources are checked before freeze.
- `src/security_remediation/verification.py` copies each source snapshot to a fresh temporary tree. It checks `uv lock --check`, wheel-only `uv sync --locked --no-install-project`, `uv pip check`, and exact lock-vs-installed package inventory. Configured checks run with the selected venv's `python`; the pilot uses `unittest` with a nonzero `Ran N tests` count that must not shrink. Optional lint/build need trusted checks in policy; **the pilot configures neither**. Verification rejects observed file mutation before reporting success.
- Pinned **pip-audit 2.10.1** runs outside the target venv with `--path` against its installed site-packages, not against `uv.lock` directly. Parsed dependency names/versions must equal installed inventory. Baseline must show an alert alias for the target; candidate version must be outside its affected range and show no target alias; a new normalized finding blocks verification. Valid vulnerability output (including scanner exit 1) is not treated as a service failure. Evidence includes base/candidate identity, policy and skill digests, tool/Python/platform values, command statuses and scanner timestamp. Existing unrelated findings are disclosed. Scanner coverage and alias normalization remain bounded to this implementation's parsing; advisory feeds may change between runs.

## Current limits and differences from the original design

| Original aspiration | Current fact / gate |
| --- | --- |
| Isolated harness/worker for installs, tests and agent tools | **Absent.** Everything runs on the host; pi and untrusted package/test code can access OS-user resources and potentially saved credentials/state. Environment filtering, path validation and process-group killing do not confer sandboxing. [Compatibility notes](harness-compatibility.md). |
| Demonstrated agent-authored repair | Only a no-tools pi skill smoke was live. Routine pi responses use fakes; the live urllib3 pilot was a **deterministic** upgrade, zero pi calls. |
| Groups/extras, compatible transitive parent updates, general repository support | Explicitly unsupported/blocked in this pilot; first-party source edits are permitted by validation but have not been live-proven through pi. |
| Strict end-to-end elapsed-time and child containment | `run_timeout_seconds` is checked between loop iterations; individual commands have their own timeouts, so one running command can exceed the nominal overall deadline. Process-group kill cannot contain escaped processes. |
| Test identity, advisory equivalence and severity | Currently checks a nonzero `unittest` count that does not shrink; it does not compare exact test identities or skip/xfail sets. Scanner IDs are normalized per record; equivalence of differently reported alias groups across feeds is not fully proven. Only new finding identities are blocked; worsening severity on an unchanged identity is **not** evaluated. |
| GitHub alert loading, exact-candidate PR publisher, Jenkins | **None installed.** `publication_enabled` accepts only false. No PR, merge, dismissal or Jenkins execution path. |

## Evidence and trust classification

`tests/test_local.py` covers policy/forbidden edits, budget and checkpoint recovery, malformed agent/scanner results, baseline failure, advisory ambiguity, new findings and candidate mutation using fakes. On 2026-10-01 the disposable **real** pilot upgraded urllib3 2.0.6 → 2.8.0: six baseline and six candidate checks passed, 9 → 0 reported findings, and `git apply --check` accepted the generated patch. These observations do not certify other repositories, model-generated edits, complete security, credential isolation, or future scanner results. Use `uv run --locked pytest` and `uv run --locked ruff check src tests/test_local.py` to recheck local code; run the real pilot via README when network/tool versions are available.
