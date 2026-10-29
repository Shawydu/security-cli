import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "skills/vulnerability-remediation/scan_diff.py"
spec = importlib.util.spec_from_file_location("scan_diff", SCRIPT)
scan_diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_diff)


def scan(path, packages):
    """packages: {(ecosystem, name, version): [(id, [aliases])]} in osv-scanner JSON shape."""
    path.write_text(json.dumps({"results": [{"source": {"path": "package-lock.json", "type": "lockfile"}, "packages": [
        {"package": {"ecosystem": eco, "name": name, "version": version},
         "vulnerabilities": [{"id": vid, "aliases": aliases} for vid, aliases in vulns]}
        for (eco, name, version), vulns in packages.items()]}]}))
    return str(path)


def test_scan_diff_exit_codes(tmp_path, capsys):
    target = ("GHSA-aaaa-bbbb-cccc", ["CVE-2024-0001"])
    unrelated = ("GHSA-dddd-eeee-ffff", [])
    base = scan(tmp_path / "b.json", {("npm", "lodash", "4.17.20"): [target], ("npm", "minimist", "1.2.0"): [unrelated]})
    fixed = scan(tmp_path / "c.json", {("npm", "lodash", "4.17.21"): [], ("npm", "minimist", "1.2.0"): [unrelated]})
    assert scan_diff.main([base, fixed, "--advisory", "cve-2024-0001"]) == 0

    # unrelated advisory re-reported under its alias still counts as the same finding
    alias_renamed = scan(tmp_path / "a.json", {("npm", "lodash", "4.17.21"): [], ("npm", "minimist", "1.2.0"): [("OSV-1", ["GHSA-dddd-eeee-ffff"])]})
    assert scan_diff.main([base, alias_renamed, "--advisory", "GHSA-aaaa-bbbb-cccc"]) == 0

    still = scan(tmp_path / "s.json", {("npm", "lodash", "4.17.20"): [target]})
    assert scan_diff.main([base, still, "--advisory", "GHSA-aaaa-bbbb-cccc"]) == 1

    new = scan(tmp_path / "n.json", {("npm", "lodash", "4.17.21"): [], ("npm", "qs", "6.0.0"): [("GHSA-new0-new0-new0", [])]})
    assert scan_diff.main([base, new, "--advisory", "GHSA-aaaa-bbbb-cccc"]) == 1
    assert "npm/qs: GHSA-NEW0-NEW0-NEW0" in capsys.readouterr().out

    assert scan_diff.main([base, fixed, "--advisory", "GHSA-not0-in00-base"]) == 1
    empty = tmp_path / "e.json"
    empty.write_text(json.dumps({"results": []}))
    assert scan_diff.main([base, str(empty), "--advisory", "GHSA-aaaa-bbbb-cccc"]) == 2
    (tmp_path / "bad.json").write_text("not json")
    assert scan_diff.main([base, str(tmp_path / "bad.json"), "--advisory", "x"]) == 2
