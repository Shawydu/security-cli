"""Source export, candidate identity, and fail-closed path/content validation."""
from __future__ import annotations

import difflib
import fnmatch
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from .contracts import Alert, Policy


class Rejected(Exception):
    pass


def source_sha(source: Path) -> str:
    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", str(source), *args], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    if git("rev-parse", "--show-toplevel") != str(source.resolve()):
        raise Rejected("source must be the root of its own Git checkout")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise Rejected("source checkout is dirty")
    return git("rev-parse", "HEAD")


def files(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(dirs)
        for dirname in dirs:
            if (Path(directory) / dirname).is_symlink():
                raise Rejected("symlink directory rejected")
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise Rejected("symlink or special file rejected")
            rel = path.relative_to(root).as_posix()
            if rel.startswith(".git/") or rel.startswith(".venv/"):
                raise Rejected("worker created Git metadata or environment")
            if path.stat().st_mode & 0o111:
                raise Rejected(f"executable file rejected: {rel}")
            if path.stat().st_size > 2_000_000:
                raise Rejected(f"oversized file: {rel}")
            result[rel] = path.read_bytes()
    return result


def export(source: Path, dest: Path, base_sha: str) -> None:
    archive = subprocess.run(["git", "-C", str(source), "archive", "--format=tar", base_sha], capture_output=True, check=True).stdout
    if len(archive) > 20_000_000:
        raise Rejected("source archive too large")
    dest.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            target = dest / member.name
            if member.name.startswith("/") or ".." in Path(member.name).parts or not (member.isfile() or member.isdir()):
                raise Rejected("unsafe Git archive entry")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if member.mode & 0o111 or member.size > 2_000_000:
                    raise Rejected("executable or oversized source file")
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as stream:
                    target.write_bytes(stream.read())
    files(dest)


def identity(root: Path) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(files(root).items()):
        digest.update(name.encode() + b"\0" + len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def _requirements(raw: dict, policy: Policy) -> dict[str, str]:
    result: dict[str, str] = {}
    arrays = [raw.get("project", {}).get("dependencies", [])]
    arrays += [raw.get("project", {}).get("optional-dependencies", {}).get(e, []) for e in policy.extras]
    arrays += [raw.get("dependency-groups", {}).get(g, []) for g in policy.dependency_groups]
    for array in arrays:
        if not isinstance(array, list):
            raise Rejected("invalid dependency array")
        for item in array:
            if not isinstance(item, str):
                raise Rejected("unsupported dependency declaration")
            req = Requirement(item)
            if req.url is not None:
                raise Rejected("URL/path/VCS dependency denied")
            name = canonicalize_name(req.name)
            result[name] = item
    return result


def _toml_ok(before: bytes, after: bytes, policy: Policy, alert: Alert) -> None:
    old = tomllib.loads(before.decode())
    new = tomllib.loads(after.decode())
    _requirements(new, policy)
    old_deps = _requirements(old, policy)
    new_deps = _requirements(new, policy)
    # Only the target may change in the first pilot. Parent upgrades remain a documented blocked case.
    if {k: v for k, v in old_deps.items() if k != alert.package} != {k: v for k, v in new_deps.items() if k != alert.package}:
        raise Rejected("unrelated dependency declarations changed")
    if alert.package not in new_deps:
        raise Rejected("target dependency removed")
    for obj in (old, new):
        obj.get("project", {}).pop("dependencies", None)
        obj.get("project", {}).pop("optional-dependencies", None)
        obj.pop("dependency-groups", None)
    if old != new:
        raise Rejected("non-dependency pyproject fields changed")


def lock_inventory(root: Path) -> dict[str, str]:
    try:
        lock = tomllib.loads((root / "uv.lock").read_text())
        inventory: dict[str, str] = {}
        for package in lock["package"]:
            name = canonicalize_name(package["name"])
            source = package["source"]
            if source.get("registry") != "https://pypi.org/simple":
                # Local root project in a virtual uv project is not a third-party package.
                if source != {"virtual": "."}:
                    raise Rejected(f"unsupported source for {name}: {source}")
                continue
            if name in inventory:
                raise Rejected("multi-platform duplicate lock name unsupported by pilot")
            version = Version(package["version"])
            if version.is_prerelease or version.is_devrelease:
                raise Rejected("pre-release/dev package denied")
            wheels = package.get("wheels", [])
            if not wheels or any(not wheel.get("url", "").startswith("https://files.pythonhosted.org/") or not wheel.get("hash", "").startswith("sha256:") for wheel in wheels):
                raise Rejected("missing or unapproved wheel artifact")
            sdist = package.get("sdist", {})
            if sdist and not sdist.get("url", "").startswith("https://files.pythonhosted.org/"):
                raise Rejected("unapproved sdist artifact")
            inventory[name] = package["version"]
        return inventory
    except (KeyError, ValueError, OSError, TypeError) as exc:
        raise Rejected("malformed or unsupported uv.lock") from exc


def validate(base: Path, work: Path, policy: Policy, alert: Alert) -> tuple[list[str], str]:
    original, edited = files(base), files(work)
    changed = [p for p in sorted(original.keys() | edited.keys()) if original.get(p) != edited.get(p)]
    if not changed or len(changed) > policy.max_changed_files:
        raise Rejected("empty or oversized candidate file set")
    lines = 0
    for path in changed:
        if path not in original or path not in edited:
            raise Rejected("file creation/deletion/rename unsupported by pilot")
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in policy.allowed_edit_paths):
            raise Rejected(f"forbidden edit: {path}")
        segments = Path(path).parts
        if any(part in {"tests", "test", ".github", "ci", "skills", "config", "workflows"} for part in segments) or Path(path).name.startswith("test_") or Path(path).name in {"AGENTS.md", "CLAUDE.md", "pytest.ini", "ruff.toml", "setup.cfg", "tox.ini"}:
            raise Rejected(f"forbidden test/CI/policy edit: {path}")
        try:
            before, after = original[path].decode(), edited[path].decode()
        except UnicodeDecodeError as exc:
            raise Rejected("binary edit rejected") from exc
        lines += len(list(difflib.unified_diff(before.splitlines(), after.splitlines())))
    if lines > policy.max_changed_lines:
        raise Rejected("candidate exceeds change-line budget")
    if "pyproject.toml" in changed:
        _toml_ok(original["pyproject.toml"], edited["pyproject.toml"], policy, alert)
    prior, current = lock_inventory(base), lock_inventory(work)
    if len({k for k in prior.keys() | current.keys() if prior.get(k) != current.get(k)}) > policy.max_dependency_version_changes:
        raise Rejected("too many resolved-version changes")
    for package, version in prior.items():
        if package not in current or Version(current[package]) < Version(version):
            raise Rejected("dependency removed or downgraded")
        before, after = Version(version), Version(current[package])
        if before.release[0] != after.release[0] or (before.release[0] == 0 and len(before.release) > 1 and len(after.release) > 1 and before.release[1] != after.release[1]):
            raise Rejected("major or 0.x minor migration requires manual handling")
    if alert.package not in prior or alert.package not in current:
        raise Rejected("target absent from selected lock")
    if Version(current[alert.package]) <= Version(prior[alert.package]):
        raise Rejected("target did not upgrade")
    patch: list[str] = []
    for path in changed:
        patch.append(f"diff --git a/{path} b/{path}\n")
        patch.extend(difflib.unified_diff(original[path].decode().splitlines(keepends=True), edited[path].decode().splitlines(keepends=True), fromfile="a/" + path, tofile="b/" + path))
    return changed, "".join(patch)


def freeze(work: Path, destination: Path) -> str:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(work, destination, symlinks=False)
    return identity(destination)
