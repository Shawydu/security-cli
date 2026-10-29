import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "skills/security-triage/triage.py"
spec = importlib.util.spec_from_file_location("triage", SCRIPT)
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


def alert(number, package, severity, ghsa, state="open", patched="2.0.7"):
    return {
        "number": number,
        "state": state,
        "html_url": f"https://github.com/o/r/security/dependabot/{number}",
        "dependency": {"package": {"ecosystem": "pip", "name": package}, "manifest_path": "uv.lock"},
        "security_advisory": {"ghsa_id": ghsa, "cve_id": None, "summary": f"{package} bug", "severity": severity,
                              "identifiers": [{"type": "GHSA", "value": ghsa}]},
        "security_vulnerability": {"severity": severity, "vulnerable_version_range": "< 2.0.7",
                                   "first_patched_version": {"identifier": patched} if patched else None},
    }


def finding(fingerprint, verdict, line=1, severity="medium", text="handler"):
    loc = {"file": "app.py", "line": line, "description": text}
    base = {"verdict": verdict, "fingerprint": fingerprint, "title": fingerprint, "description": text,
            "trace": [{"kind": "sink", "scope": "f", **loc}], "evidence": [loc]}
    if verdict == "confirmed":
        base |= {"root_cause": text, "severity": {"overall_severity": severity}, "confidence": {"score": "high"}}
    return base


def test_ranks_links_and_filters(tmp_path):
    (tmp_path / "app.py").write_text("one\ntwo\n")
    alerts = [[alert(1, "urllib3", "medium", "GHSA-g4mx-q9vg-27p4")],
              [alert(2, "requests", "high", "GHSA-9wx4-h78v-vm56"), alert(3, "idna", "high", "GHSA-jjg7-2v4v-x38h", "fixed"),
               alert(4, "ecdsa", "critical", "GHSA-wj6h-64fc-37mp", patched=None)]]
    findings = [
        finding("ssrf", "confirmed", severity="high", text="redirect via urllib3 per GHSA-G4MX-Q9VG-27P4"),
        finding("maybe", "needs_validation", text="requests session reuse"),
        finding("gone", "confirmed", line=99),
        finding("nope", "rejected"),
    ]
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(alerts))
    result = triage.triage(triage.flatten(json.loads(path.read_text())), findings, tmp_path)
    by_id = {item["id"]: item for item in result["items"]}

    assert result["dropped"] == {"dependabot_not_open": 1, "audit_rejected": 1}
    assert [item["id"] for item in result["items"]][:3] == ["audit:ssrf", "dependabot:2", "dependabot:1"]
    assert by_id["dependabot:4"]["action"] == "manual-no-patch"
    assert by_id["audit:gone"]["action"] == "stale-reaudit"
    assert by_id["audit:maybe"]["action"] == "validate-first" and by_id["audit:maybe"]["severity"] == "unrated"
    assert {"id": "audit:ssrf", "kind": "same-advisory"} in by_id["dependabot:1"]["links"]
    assert by_id["dependabot:2"]["links"] == [{"id": "audit:maybe", "kind": "mentions-package"}]
    assert "| 1 | high | remediate-code-finding |" in triage.markdown(result)


def test_stale_check_rejects_paths_outside_repo(tmp_path):
    escaped = finding("x", "confirmed")
    escaped["trace"][0]["file"] = "../../etc/passwd"
    assert triage.stale_locations(escaped, tmp_path.resolve())[0].endswith("(missing)")
