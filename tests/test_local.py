from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from security_remediation import runner
from security_remediation.contracts import Alert, OperationState, Policy, Status, Verification
from security_remediation.harness import HarnessError, invoke
from security_remediation.fixture import run_fixture
from security_remediation.verification import OperationalError, _audit, decide
from security_remediation.process import CommandTimeout, run as run_command
from security_remediation.state import Conflict, Store, atomic_json
from security_remediation.workspace import Rejected, export, identity, validate

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "tests/fixtures/pilot"
ALERT = ROOT / "tests/fixtures/alerts/urllib3.json"
POLICY = ROOT / "config/pilot-policy.example.yaml"


def git_source(tmp: Path) -> Path:
    source = tmp / "source"
    shutil.copytree(PILOT, source)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "baseline"], check=True)
    return source


def patch_lock(root: Path) -> None:
    lock = root / "uv.lock"
    before = lock.read_text()
    assert 'version = "2.0.6"' in before
    lock.write_text(before.replace('version = "2.0.6"', 'version = "2.0.7"', 1))


def inputs():
    return runner.load(ALERT, POLICY)


def test_candidate_rejects_test_config_ci_and_symlinks(tmp_path):
    alert, policy, _, _ = inputs()
    source = git_source(tmp_path)
    base = tmp_path / "base"
    export(source, base, runner.source_sha(source))
    edited = tmp_path / "edited"
    shutil.copytree(base, edited)
    patch_lock(edited)
    validate(base, edited, policy, alert)
    (edited / "tests/test_pilot.py").write_text("assert True\n")
    with pytest.raises(Rejected, match="forbidden"):
        validate(base, edited, policy, alert)
    shutil.copy2(base / "tests/test_pilot.py", edited / "tests/test_pilot.py")
    (edited / "src/pilot/__init__.py").unlink()
    (edited / "src/pilot/__init__.py").symlink_to("/etc/passwd")
    with pytest.raises(Rejected, match="symlink"):
        validate(base, edited, policy, alert)


def test_candidate_rejects_non_dependency_pyproject_and_downgrade(tmp_path):
    alert, policy, _, _ = inputs()
    source = git_source(tmp_path)
    base = tmp_path / "base"
    export(source, base, runner.source_sha(source))
    edited = tmp_path / "edited"
    shutil.copytree(base, edited)
    patch_lock(edited)
    pyproject = edited / "pyproject.toml"
    pyproject.write_text(pyproject.read_text() + "\n[tool.pytest.ini_options]\naddopts = '-x'\n")
    with pytest.raises(Rejected, match="non-dependency"):
        validate(base, edited, policy, alert)
    pyproject.write_bytes((base / "pyproject.toml").read_bytes())
    (edited / "uv.lock").write_text((base / "uv.lock").read_text().replace('version = "2.0.6"', 'version = "2.0.5"', 1))
    with pytest.raises(Rejected, match="downgraded"):
        validate(base, edited, policy, alert)


def test_attempts_survive_restart(tmp_path):
    store = Store(tmp_path, "local")
    with store.lock():
        state = store.save(OperationState(operation_id="local", base_sha="abc", alert_digest="a", policy_digest="p"), reason="start")
        store.reserve(state, 3)
    with store.lock():
        loaded = store.load()
        assert loaded.attempts == 1
        assert store.reserve(loaded, 3).attempts == 2
    with store.lock():
        assert store.reserve(store.load(), 3).attempts == 3
        assert store.reserve(store.load(), 3).status == Status.EXHAUSTED
    (store.file).write_text("{broken")
    with store.lock(), pytest.raises(Conflict, match="corrupt"):
        store.load()


def fake_verified(base: Path, candidate: Path, alert: Alert, policy: Policy, env: dict, policy_digest: str, base_sha: str) -> Verification:
    return Verification(candidate_digest=identity(candidate), base_sha=base_sha, policy_digest=policy_digest, python_version=policy.python_version, uv_version="0.12.12", scanner="pip-audit 2.10.1", checks=[], target_resolved=True, verified=True)


def fake_baseline(*args, **kwargs):
    return [], set(), set(), 1


def test_checkpoint_after_crash_reconstructs_and_reverifies(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    alert, policy, alert_digest, policy_digest = inputs()
    sha = runner.source_sha(source)
    op = runner.digest(f"{alert.repository}:{alert.number}:default".encode())[:24]
    store = Store(tmp_path / "state", op)
    with store.lock():
        state = store.save(OperationState(operation_id=op, base_sha=sha, alert_digest=alert_digest, policy_digest=policy_digest, skill_digest=runner.digest((ROOT / 'skills/vulnerability-remediation/SKILL.md').read_bytes())), reason="start")
        export(source, store.root / "base", sha)
        state = store.reserve(state, 3)
        shutil.copytree(store.root / "base", store.root / "candidate")
        patch_lock(store.root / "candidate")
        changed, patch = validate(store.root / "base", store.root / "candidate", policy, alert)
        atomic_json(store.root / "candidate.json", {"digest": identity(store.root / "candidate"), "paths": changed, "patch": patch, "agent": None})
        # Crash: state remains agent_running, with one reserved attempt and complete candidate files.
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", fake_baseline)
    monkeypatch.setattr(runner, "decide", fake_verified)
    monkeypatch.setattr(runner, "invoke", lambda *args: pytest.fail("must not reinvoke pi"))
    result = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out")
    assert result.outcome == Status.VERIFIED and result.attempts == 1
    assert runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out").attempts == 1


def test_interrupted_reservation_consumes_next_attempt(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    alert, _, alert_digest, policy_digest = inputs()
    sha = runner.source_sha(source)
    op = runner.digest(f"{alert.repository}:{alert.number}:default".encode())[:24]
    store = Store(tmp_path / "state", op)
    with store.lock():
        state = store.save(OperationState(operation_id=op, base_sha=sha, alert_digest=alert_digest, policy_digest=policy_digest, skill_digest=runner.digest((ROOT / "skills/vulnerability-remediation/SKILL.md").read_bytes())), reason="seed")
        store.reserve(state, 3)  # crash here; no candidate checkpoint
        export(source, store.root / "base", sha)
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", fake_baseline)
    monkeypatch.setattr(runner, "invoke", lambda *args: (_ for _ in ()).throw(HarnessError("fake invalid response")))
    result = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out")
    assert result.attempts == 2 and result.outcome == Status.BLOCKED


def test_explicit_new_operation_preserves_history(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", lambda *args, **kw: (_ for _ in ()).throw(Rejected("baseline failure")))
    first = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out1")
    second = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out2", operation_id="operator-retry-1", new_operation_reason="investigate false baseline")
    assert first.operation_id != second.operation_id
    assert (tmp_path / "state/operations" / first.operation_id / "state.json").exists()
    assert (tmp_path / "state/operations" / second.operation_id / "state.json").exists()
    with pytest.raises(Rejected, match="together"):
        runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out3", operation_id="bad")


def test_candidate_mutation_during_checks_cannot_verify(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    alert, policy, a, p = inputs()
    sha = runner.source_sha(source)
    op = runner.digest(f"{alert.repository}:{alert.number}:default".encode())[:24]
    store = Store(tmp_path / "state", op)
    with store.lock():
        store.save(OperationState(operation_id=op, base_sha=sha, alert_digest=a, policy_digest=p, skill_digest=runner.digest((ROOT / "skills/vulnerability-remediation/SKILL.md").read_bytes())), reason="seed")
        export(source, store.root / "base", sha)
        shutil.copytree(store.root / "base", store.root / "candidate")
        patch_lock(store.root / "candidate")
        changed, patch = validate(store.root / "base", store.root / "candidate", policy, alert)
        atomic_json(store.root / "candidate.json", {"digest": identity(store.root / "candidate"), "paths": changed, "patch": patch, "agent": None})
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", fake_baseline)
    def corrupt(base, candidate, alert, policy, env, digest, sha):
        evidence = fake_verified(base, candidate, alert, policy, env, digest, sha)
        (candidate / "src/pilot/__init__.py").write_text("# changed after check\n")
        return evidence
    monkeypatch.setattr(runner, "decide", corrupt)
    with pytest.raises(Conflict, match="identity changed"):
        runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out")


def test_failing_baseline_blocks_before_model(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", lambda *args, **kw: (_ for _ in ()).throw(Rejected("zero tests")))
    monkeypatch.setattr(runner, "invoke", lambda *args: pytest.fail("model must not run"))
    result = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out")
    assert result.outcome == Status.BLOCKED and result.attempts == 0


def test_exhausted_does_not_reset_budget(tmp_path, monkeypatch):
    source = git_source(tmp_path)
    alert, policy, a, p = inputs()
    sha = runner.source_sha(source)
    op = runner.digest(f"{alert.repository}:{alert.number}:default".encode())[:24]
    store = Store(tmp_path / "state", op)
    with store.lock():
        store.save(OperationState(operation_id=op, base_sha=sha, alert_digest=a, policy_digest=p, skill_digest=runner.digest((ROOT / 'skills/vulnerability-remediation/SKILL.md').read_bytes()), attempts=3, status=Status.AGENT_RUNNING), reason="seed")
        export(source, store.root / "base", sha)
    monkeypatch.setattr(runner, "uv_binary", lambda: "uv")
    monkeypatch.setattr(runner, "inspect", fake_baseline)
    monkeypatch.setattr(runner, "invoke", lambda *args: pytest.fail("budget exhausted"))
    result = runner.run(alert_file=ALERT, source=source, policy_file=POLICY, state_dir=tmp_path / "state", output=tmp_path / "out")
    assert result.outcome == Status.EXHAUSTED and result.attempts == 3


def test_fixture_modes_are_simulated_and_offline(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: pytest.fail("network in fixture"))
    for case, expected in (("direct", "simulated_candidate"), ("forbidden", "blocked"), ("scanner-error", "infrastructure_error"), ("baseline-failure", "blocked")):
        result = run_fixture(PILOT, tmp_path / case, case)
        assert result["outcome"] == expected and result["simulated"] and not result["verified"]


def test_scanner_error_is_not_a_clean_scan(tmp_path, monkeypatch):
    class Fake:
        returncode = 1
        stdout = ""
        stderr = "service unavailable"
    monkeypatch.setattr("security_remediation.verification.run_command", lambda *args, **kwargs: Fake())
    with pytest.raises(OperationalError, match="malformed"):
        _audit(tmp_path, {"urllib3": "2.0.6"}, tmp_path, {})


def test_alias_ambiguity_and_new_finding_block(tmp_path, monkeypatch):
    alert, policy, _, policy_digest = inputs()
    source = git_source(tmp_path)
    base = tmp_path / "base"
    export(source, base, runner.source_sha(source))
    candidate = tmp_path / "candidate"
    shutil.copytree(base, candidate)
    patch_lock(candidate)
    observations = [([], set(), set(), 1), ([], {"urllib3:CVE-NEW"}, set(), 1)]
    monkeypatch.setattr("security_remediation.verification.inspect", lambda *args, **kwargs: observations.pop(0))
    with pytest.raises(Rejected, match="not present"):
        decide(base, candidate, alert, policy, {}, policy_digest, runner.source_sha(source))
    observations[:] = [([], {"urllib3:CVE-2023-45803"}, {"urllib3:GHSA-G4MX-Q9VG-27P4"}, 1), ([], {"urllib3:CVE-NEW"}, set(), 1)]
    result = decide(base, candidate, alert, policy, {}, policy_digest, runner.source_sha(source))
    assert not result.verified


def test_timeout_is_operational_and_kills_worker(tmp_path):
    with pytest.raises(CommandTimeout):
        run_command(["/bin/sh", "-c", "sleep 10"], cwd=tmp_path, env={"PATH": "/usr/bin:/bin"}, timeout=1)


def test_malformed_pi_output_is_not_success(tmp_path, monkeypatch):
    binpath = tmp_path / "pi"
    binpath.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 0.99.1; else echo 'not JSON'; fi\n")
    binpath.chmod(0o755)
    monkeypatch.setattr("security_remediation.harness.shutil.which", lambda executable: str(binpath))
    alert, policy, _, _ = inputs()
    with pytest.raises(HarnessError, match="malformed"):
        invoke(tmp_path, alert, policy, ROOT / "skills/vulnerability-remediation/SKILL.md", "", {})
