import importlib.util
import json
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "skills/vulnerability-remediation/remediate.py"
spec = importlib.util.spec_from_file_location("remediate", SCRIPT)
remediate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remediate)

ADVISORY = "GHSA-aaaa-bbbb-cccc"
OSV = """#!/usr/bin/env python3
import json, sys
vulnerable = '1.0.0' in open('uv.lock').read()
vulns = [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2024-0001"]}] if vulnerable else []
print(json.dumps({"results": [{"packages": [{"package": {"ecosystem": "PyPI", "name": "demo", "version": "1.0.0" if vulnerable else "2.0.0"}, "vulnerabilities": vulns}]}]}))
sys.exit(1 if vulnerable else 0)
"""
UV = """#!/usr/bin/env python3
import sys
version = sys.argv[-1].split('==')[1]
open('uv.lock', 'w').write(f'version = "{version}"\\n')
EXTRA
"""


def setup(tmp_path, monkeypatch, extra=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("osv-scanner", OSV), ("uv", UV.replace("EXTRA", extra))):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ["PATH"])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (repo / "uv.lock").write_text('version = "1.0.0"\n')
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo, tmp_path / "out"


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def fix(repo, out, check="true", advisory=ADVISORY):
    return remediate.main(["fix", "--repo", str(repo), "--out", str(out), "--package", "demo", "--advisory", advisory,
                           "--version", "2.0.0", "--ecosystem", "uv", "--check", check])


def result(out):
    return json.loads((out / "result.json").read_text())


def test_fix_success(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch)
    assert fix(repo, out) == 0
    assert result(out)["status"] == "fixed"
    assert git(repo, "branch", "--show-current").strip() == "security/demo-ghsa-aaaa-bbbb-cccc"
    assert git(repo, "log", "-1", "--format=%s").startswith("fix(deps): remediate demo")
    assert "2.0.0" in (repo / "uv.lock").read_text()


def test_check_fails_after_fix(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch)
    assert fix(repo, out, check="! grep -q 2.0.0 uv.lock") == 1
    assert result(out)["reason"] == "check-failed"


def test_cannot_start(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch)
    assert fix(repo, out, advisory="GHSA-zzzz-zzzz-zzzz") == 2
    (repo / "dirty.txt").write_text("x")
    assert fix(repo, out) == 2


def test_out_of_scope_change(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch, extra="open('README.md', 'w').write('x')")
    assert fix(repo, out) == 1
    assert result(out)["reason"] == "out-of-scope-change"


def test_scanner_crash_still_writes_result(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch)
    assert fix(repo, out) == 0
    (tmp_path / "bin" / "osv-scanner").write_text("#!/bin/sh\nexit 127\n")
    state = result(out)
    assert remediate.main(["verify", "--repo", str(repo), "--out", str(out)]) == 1
    assert result(out)["reason"] == "osv-scanner failed with exit 127" and state["status"] == "fixed"


def escalated(tmp_path, monkeypatch):
    repo, out = setup(tmp_path, monkeypatch)
    assert fix(repo, out, check="! grep -q 2.0.0 uv.lock || test -f src/ok.py") == 1
    return repo, out


def test_verify_rejects_test_edits(tmp_path, monkeypatch):
    repo, out = escalated(tmp_path, monkeypatch)
    (repo / "tests").mkdir()
    (repo / "tests/test_x.py").write_text("pass\n")
    assert remediate.main(["verify", "--repo", str(repo), "--out", str(out)]) == 1
    assert result(out)["reason"].startswith("protected-files-changed")


def test_verify_accepts_agent_fix(tmp_path, monkeypatch):
    repo, out = escalated(tmp_path, monkeypatch)
    (repo / "src").mkdir()
    (repo / "src/ok.py").write_text("pass\n")
    assert remediate.main(["verify", "--repo", str(repo), "--out", str(out)]) == 0
    assert result(out)["status"] == "fixed-with-agent"
    assert git(repo, "status", "--porcelain") == ""
