"""Network-free, explicitly simulated CLI exercise; never emits verified evidence."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from .contracts import Alert, Policy
from .state import atomic_json
from .workspace import Rejected, validate


def run_fixture(fixture: Path, output: Path, case: str = "direct") -> dict:
    root = Path(__file__).resolve().parents[2]
    alert = Alert.model_validate_json((root / "tests/fixtures/alerts/urllib3.json").read_bytes())
    import yaml
    policy = Policy.model_validate(yaml.safe_load((root / "config/pilot-policy.example.yaml").read_text()))
    if case not in {"direct", "forbidden", "scanner-error", "baseline-failure"}:
        raise Rejected("unknown fixture case")
    with tempfile.TemporaryDirectory(prefix="remediation-offline-") as scratch:
        base, edited = Path(scratch) / "base", Path(scratch) / "edited"
        shutil.copytree(fixture, base)
        shutil.copytree(fixture, edited)
        result = {"schema_version": 1, "simulated": True, "verified": False, "case": case, "network_calls": 0}
        if case == "baseline-failure":
            result.update({"outcome": "blocked", "reason": "fake baseline: zero tests"})
        else:
            lock = edited / "uv.lock"
            lock.write_text(lock.read_text().replace('version = "2.0.6"', 'version = "2.0.7"', 1))
            if case == "forbidden":
                (edited / "tests/test_pilot.py").write_text("assert True\n")
            try:
                changed, _ = validate(base, edited, policy, alert)
                if case == "scanner-error":
                    result.update({"outcome": "infrastructure_error", "reason": "fake scanner: malformed response"})
                else:
                    result.update({"outcome": "simulated_candidate", "changed_paths": changed, "reason": "diff accepted by simulated fixture; no verification performed"})
            except Rejected as exc:
                result.update({"outcome": "blocked", "reason": str(exc)})
        output.mkdir(parents=True, exist_ok=True)
        atomic_json(output / "fixture-result.json", result)
        return result
