"""One deterministic, compatible, direct-package uv upgrade for the pilot."""
from __future__ import annotations

import shutil
import subprocess
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from .contracts import Alert, Policy
from .process import run as run_command
from .workspace import Rejected, lock_inventory

EXPECTED_UV = "0.12.12"


def uv_binary() -> str:
    binary = shutil.which("uv")
    if not binary:
        raise Rejected("uv is not installed")
    version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout
    if not version.startswith("uv " + EXPECTED_UV + " "):
        raise Rejected(f"expected uv {EXPECTED_UV}, got {version.strip()}")
    return binary


def _selection(policy: Policy) -> list[str]:
    args = ["--no-default-groups"]
    for name in policy.dependency_groups:
        args.extend(["--group", name])
    for name in policy.extras:
        args.extend(["--extra", name])
    return args


def try_compatible_upgrade(base: Path, work: Path, alert: Alert, policy: Policy, env: dict[str, str]) -> bool:
    raw = tomllib.loads((base / "pyproject.toml").read_text())
    requirements = [Requirement(d) for d in raw.get("project", {}).get("dependencies", [])]
    matches = [r for r in requirements if r.name.lower().replace("_", "-") == alert.package]
    if len(matches) != 1 or matches[0].url:
        return False
    fixed = min(Version(v) for v in alert.patched_versions)
    if fixed not in matches[0].specifier or fixed.is_prerelease:
        return False
    binary = uv_binary()
    args = [binary, "lock", "--python", policy.python_version, "--no-build", "--no-python-downloads", "--index-url", policy.package_index, "--upgrade-package", alert.package]
    result = run_command(args, cwd=work, env=env, timeout=180)
    if result.returncode:
        return False
    old, new = lock_inventory(base), lock_inventory(work)
    if alert.package not in new or Version(new[alert.package]) <= Version(old[alert.package]):
        return False
    if Version(new[alert.package]) in SpecifierSet(alert.affected_range):
        return False
    return True
