"""Local-only state machine. Publication is intentionally absent."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

import yaml

from .contracts import Alert, OperationState, Policy, RunResult, Status
from .dependencies import try_compatible_upgrade, uv_binary
from .harness import HarnessError, invoke
from .process import CommandTimeout, OutputLimit, run as run_command
from .state import Conflict, Store, atomic_json
from .verification import FunctionalFailure, OperationalError, decide, inspect
from .workspace import Rejected, export, freeze, identity, lock_inventory, source_sha, validate


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _env(*, agent: bool = False) -> dict[str, str]:
    if agent:
        return {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "GH_", "JENKINS_"))}
    return {key: os.environ[key] for key in ("PATH", "LANG", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE") if key in os.environ}


def load(alert_file: Path, policy_file: Path) -> tuple[Alert, Policy, str, str]:
    alert_raw = alert_file.read_bytes()
    policy_raw = policy_file.read_bytes()
    alert = Alert.model_validate_json(alert_raw)
    policy = Policy.model_validate(yaml.safe_load(policy_raw))
    if alert.repository != policy.repository or not any(check.id == "tests" for check in policy.required_checks):
        raise Rejected("policy repository/tests do not match alert")
    if len({c.id for c in policy.required_checks}) != len(policy.required_checks):
        raise Rejected("duplicate check IDs")
    if policy.dependency_groups or policy.extras:
        raise Rejected("pilot supports only default runtime dependencies; group/extra projection not implemented")
    return alert, policy, digest(alert_raw), digest(policy_raw)


def _result(out: Path, state: OperationState, reason: str, *, verification: str | None = None, patch: str | None = None) -> RunResult:
    result = RunResult(operation_id=state.operation_id, outcome=state.status, reason=reason[:500], attempts=state.attempts, candidate_digest=state.candidate_digest, verification=verification, patch=patch)
    out.mkdir(parents=True, exist_ok=True)
    atomic_json(out / "run-result.json", result.model_dump(mode="json"))
    return result


def _report(out: Path, alert: Alert, base_sha: str, verification: dict, attempts: int, base: Path, candidate: Path, paths: list[str]) -> None:
    text = f"# Local remediation report\n\nAlert: {alert.repository} #{alert.number}, {alert.package} ({', '.join(alert.advisory_ids)})\n\nBase: `{base_sha}`\nCandidate: `{verification['candidate_digest']}`\nAgent calls reserved: {attempts}\nScanner observation: {verification['scanner_timestamp']}\nVerified: **{verification['verified']}**\n\nChecks:\n"
    for check in verification["checks"]:
        text += f"- {check['phase']}/{check['id']}: {check['status']} (exit {check['exit_code']})\n"
    before, after = lock_inventory(base), lock_inventory(candidate)
    versions = [f"{name}: {old} -> {after.get(name, '<removed>')}" for name, old in sorted(before.items()) if after.get(name) != old]
    text += "\nChanged paths: " + ", ".join(paths) + "\nResolved versions: " + (", ".join(versions) or "none")
    text += "\nBaseline findings: " + (", ".join(verification["baseline_findings"]) or "none") + "\nCandidate findings: " + (", ".join(verification["candidate_findings"]) or "none") + "\n\nSupervised local run only: target code and dependencies were not sandboxed; this is not evidence of unattended credential isolation or comprehensive security.\n"
    (out / "report.md").write_text(text)


def run(*, alert_file: Path, source: Path, policy_file: Path, state_dir: Path, output: Path, operation_id: str | None = None, new_operation_reason: str | None = None) -> RunResult:
    source, state_dir, output, policy_file = (p.resolve() for p in (source, state_dir, output, policy_file))
    if any(_inside(p, source) or _inside(source, p) for p in (state_dir, output)) or _inside(policy_file, source):
        raise Rejected("policy/state/output must be outside the source checkout")
    alert, policy, alert_digest, policy_digest = load(alert_file, policy_file)
    base_sha = source_sha(source)
    uv_binary()
    if bool(operation_id) != bool(new_operation_reason):
        raise Rejected("new operation ID and human reason must be supplied together")
    if operation_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", operation_id):
        raise Rejected("invalid local operation ID")
    if new_operation_reason and len(new_operation_reason) > 300:
        raise Rejected("new-operation reason too long")
    opid = digest(f"{alert.repository}:{alert.number}:{operation_id or 'default'}".encode())[:24]
    store = Store(state_dir, opid)
    skill = Path(__file__).resolve().parents[2] / "skills/vulnerability-remediation/SKILL.md"
    skill_digest = digest(skill.read_bytes())
    with store.lock():
        state = store.load()
        if state is None:
            state = store.save(OperationState(operation_id=opid, base_sha=base_sha, alert_digest=alert_digest, policy_digest=policy_digest, skill_digest=skill_digest, new_operation_reason=new_operation_reason or ""), reason="created operation: " + (new_operation_reason or "initial"))
        elif (state.base_sha, state.alert_digest, state.policy_digest, state.skill_digest) != (base_sha, alert_digest, policy_digest, skill_digest):
            raise Conflict("base, alert or policy changed; new operation requires deliberate human reset")
        base = store.root / "base"
        candidate = store.root / "candidate"
        marker = store.root / "candidate.json"
        if not base.exists():
            if state.status != Status.BASELINE:
                raise Conflict("saved base snapshot missing")
            export(source, base, base_sha)
        if marker.exists():
            manifest = json.loads(marker.read_bytes())
            if not candidate.exists() or identity(candidate) != manifest.get("digest"):
                raise Conflict("candidate checkpoint missing/corrupt")
            actual_paths, actual_patch = validate(base, candidate, policy, alert)
            if actual_paths != manifest.get("paths") or actual_patch != manifest.get("patch"):
                raise Conflict("checkpoint patch does not match saved candidate")
            if state.candidate_digest and state.candidate_digest != manifest["digest"]:
                raise Conflict("candidate state mismatch")
            if not state.candidate_digest:
                state = store.save(state.model_copy(update={"candidate_digest": manifest["digest"], "status": Status.CANDIDATE}), reason="recovered complete candidate checkpoint")
        elif state.candidate_digest:
            raise Conflict("candidate checkpoint lost")
        if state.status in {Status.BLOCKED, Status.EXHAUSTED}:
            return _result(output, state, state.failure or state.status)
        deadline = time.monotonic() + policy.run_timeout_seconds
        env = _env()
        try:
            # Baseline must pass before any agent invocation. Inspect again on resume for fresh audit data.
            inspect(base, alert, policy, env)
            while time.monotonic() < deadline:
                if not marker.exists():
                    work = store.root / "editable"
                    if work.exists():
                        shutil.rmtree(work)
                    shutil.copytree(base, work)
                    deterministic = state.attempts == 0 and state.status in {Status.BASELINE, Status.INFRASTRUCTURE_ERROR} and try_compatible_upgrade(base, work, alert, policy, env)
                    agent_record = None
                    if not deterministic:
                        # A failed resolution may have partially modified the editable tree.
                        shutil.rmtree(work)
                        shutil.copytree(base, work)
                        if state.attempts >= policy.max_agent_attempts:
                            state = store.save(state.model_copy(update={"status": Status.EXHAUSTED, "failure": "agent invocation budget exhausted"}), reason="exhausted")
                            return _result(output, state, state.failure)
                        state = store.reserve(state, policy.max_agent_attempts)
                        agent_record = invoke(work, alert, policy, skill, state.failure, _env(agent=True))
                        # Runner regenerates lock; agent may not alter it.
                        if (work / "uv.lock").read_bytes() != (base / "uv.lock").read_bytes():
                            raise Rejected("agent edited uv.lock")
                        uv = uv_binary()
                        lock = run_command([uv, "lock", "--python", policy.python_version, "--no-build", "--no-python-downloads", "--index-url", policy.package_index, "--upgrade-package", alert.package], cwd=work, env=env, timeout=180)
                        if lock.returncode:
                            raise Rejected(f"agent change could not be resolved: {lock.stderr[-300:]}")
                    paths, patch = validate(base, work, policy, alert)
                    candidate_digest = freeze(work, candidate)
                    frozen_paths, frozen_patch = validate(base, candidate, policy, alert)
                    if (frozen_paths, frozen_patch) != (paths, patch) or identity(candidate) != candidate_digest:
                        raise Conflict("editable tree changed while freezing exact patch")
                    atomic_json(marker, {"digest": candidate_digest, "paths": paths, "patch": patch, "agent": agent_record})
                    state = store.save(state.model_copy(update={"status": Status.CANDIDATE, "candidate_digest": candidate_digest}), reason="candidate checkpoint complete")
                manifest = json.loads(marker.read_bytes())
                if identity(candidate) != manifest.get("digest") or validate(base, candidate, policy, alert) != (manifest.get("paths"), manifest.get("patch")):
                    raise Conflict("candidate/patch identity mismatch before verification")
                state = store.save(state.model_copy(update={"status": Status.VERIFYING}), reason="verification started")
                try:
                    evidence = decide(base, candidate, alert, policy, env, policy_digest, base_sha)
                    evidence = evidence.model_copy(update={"skill_sha256": skill_digest})
                except FunctionalFailure as exc:
                    if identity(candidate) != manifest["digest"]:
                        raise Conflict("candidate changed during failed check") from exc
                    state = store.save(state.model_copy(update={"status": Status.CANDIDATE, "failure": str(exc)[:500]}), reason="candidate functional check failed")
                    marker.unlink()
                    shutil.rmtree(candidate)
                    state = store.save(state.model_copy(update={"candidate_digest": None}), reason="candidate rejected; retained attempt ledger")
                    continue
                if evidence.candidate_digest != manifest["digest"] or identity(candidate) != manifest["digest"]:
                    raise Conflict("candidate identity changed during verification")
                atomic_json(store.root / "verification.json", evidence.model_dump(mode="json"))
                if evidence.verified:
                    state = store.save(state.model_copy(update={"status": Status.VERIFIED, "candidate_digest": manifest["digest"], "failure": ""}), reason="all local gates passed")
                    output.mkdir(parents=True, exist_ok=True)
                    (output / "candidate.patch").write_text(manifest["patch"])
                    atomic_json(output / "assessment.json", {"assessment": manifest["agent"]["assessment"] if manifest["agent"] else "Deterministic compatible dependency upgrade."})
                    atomic_json(output / "plan.json", {"plan": manifest["agent"]["plan"] if manifest["agent"] else "Upgrade selected locked dependency without changing declarations."})
                    atomic_json(output / "verification.json", evidence.model_dump(mode="json"))
                    _report(output, alert, base_sha, evidence.model_dump(mode="json"), state.attempts, base, candidate, manifest["paths"])
                    return _result(output, state, "verified local candidate; publication disabled", verification="verification.json", patch="candidate.patch")
                state = store.save(state.model_copy(update={"status": Status.CANDIDATE, "failure": "target unresolved or new findings"}), reason="candidate failed security gates")
                marker.unlink()
                shutil.rmtree(candidate)
                state = store.save(state.model_copy(update={"candidate_digest": None}), reason="candidate rejected; retained attempt ledger")
            raise OperationalError("run time budget exhausted")
        except (Rejected, HarnessError) as exc:
            state = store.save(state.model_copy(update={"status": Status.BLOCKED, "failure": str(exc)[:500]}), reason="eligibility or candidate rejection")
            return _result(output, state, state.failure)
        except (OperationalError, CommandTimeout, OutputLimit, OSError) as exc:
            state = store.save(state.model_copy(update={"status": Status.INFRASTRUCTURE_ERROR, "failure": str(exc)[:500]}), reason="operational failure")
            return _result(output, state, state.failure)
