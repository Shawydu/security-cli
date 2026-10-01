"""Independent selected-environment checks. No prose-based verification."""
from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from importlib.metadata import version as installed_version
import re
import shutil
from .process import CommandTimeout, OutputLimit, run as run_command
import sys
import tempfile
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from .contracts import Alert, CheckResult, Policy, Verification
from .dependencies import EXPECTED_UV, _selection, uv_binary
from .workspace import Rejected, identity, lock_inventory

SCANNER_VERSION = "2.10.1"


class OperationalError(Exception):
    pass


class FunctionalFailure(Rejected):
    """Candidate check failed; the agent may attempt a bounded repair."""


def _command(argv: list[str], cwd: Path, env: dict[str, str], timeout: int) -> tuple[int, str]:
    try:
        result = run_command(argv, cwd=cwd, env=env, timeout=timeout)
    except (CommandTimeout, OutputLimit) as exc:
        raise OperationalError(str(exc)) from exc
    output = result.stdout + "\n" + result.stderr
    return result.returncode, output[-8000:]


def _audit(site: Path, inventory: dict[str, str], cwd: Path, env: dict[str, str]) -> tuple[set[str], set[str]]:
    try:
        result = run_command([sys.executable, "-m", "pip_audit", "--path", str(site), "--format", "json", "--aliases", "on", "--strict", "--progress-spinner", "off"], cwd=cwd, env=env, timeout=180, max_output=2_000_000)
    except (CommandTimeout, OutputLimit) as exc:
        raise OperationalError(str(exc)) from exc
    code = result.returncode
    try:
        raw = json.loads(result.stdout)
    except ValueError as exc:
        raise OperationalError("scanner returned malformed or missing JSON") from exc
    if code not in (0, 1) or not isinstance(raw, dict) or not isinstance(raw.get("dependencies"), list):
        raise OperationalError("scanner service/coverage error")
    observed: dict[str, str] = {}
    findings: set[str] = set()
    aliases: set[str] = set()
    for dep in raw["dependencies"]:
        try:
            package = canonicalize_name(dep["name"])
            version = dep["version"]
            vulns = dep["vulns"]
            if package in observed:
                raise ValueError("duplicate scanner package")
            observed[package] = version
            for vuln in vulns:
                ids = {vuln["id"], *vuln.get("aliases", [])}
                if not all(isinstance(i, str) for i in ids):
                    raise ValueError("invalid advisory identifiers")
                canonical = sorted(ids)[0].upper()
                findings.add(f"{package}:{canonical}")
                aliases.update(f"{package}:{i.upper()}" for i in ids)
        except (KeyError, TypeError, ValueError) as exc:
            raise OperationalError("scanner record incomplete") from exc
    if observed != inventory:
        raise OperationalError(f"audit inventory mismatch: locked={inventory}, scanned={observed}")
    return findings, aliases


def inspect(root: Path, alert: Alert, policy: Policy, env: dict[str, str], *, baseline_tests: int | None = None) -> tuple[list[CheckResult], set[str], set[str], int]:
    start_digest = identity(root)
    phase = "baseline" if baseline_tests is None else "candidate"
    if installed_version("pip-audit") != SCANNER_VERSION:
        raise OperationalError("unexpected pip-audit version")
    uv = uv_binary()
    with tempfile.TemporaryDirectory(prefix="remediation-verify-") as scratch:
        scratch_path = Path(scratch)
        tree = scratch_path / "source"
        shutil.copytree(root, tree)
        run_env = env.copy()
        run_env["UV_PROJECT_ENVIRONMENT"] = str(scratch_path / "venv")
        run_env["PYTHONPATH"] = str(tree / "src")
        run_env["PYTHONDONTWRITEBYTECODE"] = "1"
        run_env["HOME"] = str(scratch_path / "home")
        (scratch_path / "home").mkdir()
        flags = _selection(policy)
        checks: list[CheckResult] = []
        setup = [
            ("lock", [uv, "lock", "--check", "--python", policy.python_version, "--no-build", "--no-python-downloads", "--index-url", policy.package_index]),
            ("sync", [uv, "sync", "--locked", "--no-build", "--no-install-project", "--no-python-downloads", "--python", policy.python_version, "--index-url", policy.package_index, *flags]),
            ("consistency", [uv, "pip", "check", "--python", str(scratch_path / "venv" / "bin" / "python")]),
        ]
        for name, argv in setup:
            code, output = _command(argv, tree, run_env, 180)
            checks.append(CheckResult(id=name, phase=phase, status="passed" if code == 0 else "failed", command=argv, exit_code=code, detail=output[-400:]))
            if code:
                raise Rejected(f"{name} failed: {output[-300:]}")
        inventory = lock_inventory(tree)
        python = scratch_path / "venv" / "bin" / "python"
        code, output = _command([str(python), "-c", "import json,importlib.metadata as m; print(json.dumps({d.metadata['Name'].lower().replace('_','-'): d.version for d in m.distributions()}))"], tree, run_env, 30)
        if code:
            raise OperationalError("unable to inventory installed environment")
        installed = json.loads(output.strip())
        if installed != inventory:
            raise Rejected(f"lock/installed inventory mismatch: {inventory} vs {installed}")
        checks.append(CheckResult(id="inventory", phase=phase, status="passed"))
        count = 0
        for check in policy.required_checks:
            argv = [str(python) if arg == "python" else arg for arg in check.argv]
            # Only trusted absolute executables or the selected environment interpreter are accepted.
            if argv[0] != str(python) and not Path(argv[0]).is_absolute():
                raise Rejected("required check executable must be python or absolute trusted path")
            code, output = _command(argv, tree, run_env, check.timeout_seconds)
            if check.id == "tests":
                matches = re.findall(r"Ran (\d+) tests?", output)
                if not matches or int(matches[-1]) == 0:
                    raise Rejected("test count missing or zero")
                count = int(matches[-1])
                if baseline_tests is not None and count < baseline_tests:
                    raise Rejected("test collection shrank relative to baseline")
            checks.append(CheckResult(id=check.id, phase=phase, status="passed" if code == 0 else "failed", command=argv, exit_code=code, detail=output[-600:]))
            if code:
                failure = FunctionalFailure if baseline_tests is not None else Rejected
                raise failure(f"{check.id} failed: {output[-300:]}")
        if not count:
            raise Rejected("policy must include a nonempty 'tests' check")
        site_paths = list((scratch_path / "venv" / "lib").glob("python*/site-packages"))
        if len(site_paths) != 1:
            raise OperationalError("selected site-packages path missing")
        findings, aliases = _audit(site_paths[0], inventory, tree, run_env)
        checks.append(CheckResult(id="audit", phase=phase, status="passed", command=[sys.executable, "-m", "pip_audit", "--path", str(site_paths[0]), "--format", "json", "--aliases", "on", "--strict"], exit_code=0 if not findings else 1, detail=f"{len(findings)} findings; complete selected inventory"))
        # Verification must not alter the candidate source, even through tests or package tooling.
        if identity(tree) != start_digest or identity(root) != start_digest:
            raise Rejected("source changed during verification")
        return checks, findings, aliases, count


def decide(base: Path, candidate: Path, alert: Alert, policy: Policy, env: dict[str, str], policy_digest: str, base_sha: str) -> Verification:
    baseline_checks, baseline_findings, baseline_aliases, test_count = inspect(base, alert, policy, env)
    target_ids = {f"{alert.package}:{i.upper()}" for i in alert.advisory_ids}
    if not target_ids & baseline_aliases:
        raise Rejected("target advisory not present in baseline audit")
    candidate_checks, findings, aliases, _ = inspect(candidate, alert, policy, env, baseline_tests=test_count)
    inventory = lock_inventory(candidate)
    version = Version(inventory[alert.package])
    resolved = version not in SpecifierSet(alert.affected_range) and not (target_ids & aliases)
    # Scanner identities need alias normalization across revisions; refusing unfamiliar IDs is safer.
    introduced = findings - baseline_findings
    if introduced:
        resolved = False
    return Verification(candidate_digest=identity(candidate), base_sha=base_sha, policy_digest=policy_digest, python_version=policy.python_version, platform=platform.platform(), uv_version=EXPECTED_UV, scanner=f"pip-audit {SCANNER_VERSION}", scanner_timestamp=datetime.now(timezone.utc).isoformat(), baseline_findings=sorted(baseline_findings), candidate_findings=sorted(findings), checks=baseline_checks + candidate_checks, target_resolved=resolved, verified=resolved)
