#!/usr/bin/env python3
"""Merge Dependabot alerts, osv-scanner output and security-audit findings.json into one ranked worklist.

Stdlib only, read-only: it never calls the network or edits the repository.
"""

import argparse
import json
import re
import sys
from pathlib import Path

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "informational": 0}
ADVISORY_ID = re.compile(r"\b(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|CVE-\d{4}-\d{4,})\b", re.I)


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def flatten(data):
    """Accept a plain alert array or `gh api --paginate --slurp` output (an array of pages)."""
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of Dependabot alerts")
    if data and all(isinstance(page, list) for page in data):
        return [alert for page in data for alert in page]
    return data


def dependabot_items(alerts):
    items, dropped = [], 0
    for alert in alerts:
        if alert.get("state") != "open":
            dropped += 1
            continue
        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        dependency = alert.get("dependency") or {}
        package = (dependency.get("package") or {}).get("name") or (vulnerability.get("package") or {}).get("name")
        ids = {advisory.get("ghsa_id"), advisory.get("cve_id")}
        ids |= {i.get("value") for i in advisory.get("identifiers") or []}
        patched = (vulnerability.get("first_patched_version") or {}).get("identifier")
        items.append({
            "id": f"dependabot:{alert['number']}",
            "source": "dependabot",
            "severity": (vulnerability.get("severity") or advisory.get("severity") or "low").lower(),
            "title": advisory.get("summary") or f"{package} advisory",
            "package": package,
            "ecosystem": (dependency.get("package") or {}).get("ecosystem"),
            "manifest": dependency.get("manifest_path"),
            "vulnerable_range": vulnerability.get("vulnerable_version_range"),
            "patched_version": patched,
            "advisory_ids": sorted(i.upper() for i in ids if i),
            "url": alert.get("html_url"),
            "action": "remediate-dependency" if patched else "manual-no-patch",
            "links": [],
        })
    return items, dropped


def osv_items(results):
    items = []
    for result in results:
        for pkg in result.get("packages") or []:
            info = pkg["package"]
            name, version = info["name"], info["version"]
            for group in pkg.get("groups") or []:
                gids = set(group["ids"])
                vulns = [v for v in pkg.get("vulnerabilities") or [] if v["id"] in gids]
                installed = tuple(map(int, re.findall(r"\d+", version)))
                fixed = []
                for vuln in vulns:
                    for aff in vuln.get("affected") or []:
                        if (aff.get("package") or {}).get("name", "").lower() != name.lower():
                            continue
                        for rng in aff.get("ranges") or []:
                            fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
                # shortcut: naive int-tuple compare ignores pre-release tags and epochs, upgrade to a real version parser when those matter
                newer = [f for f in fixed if tuple(map(int, re.findall(r"\d+", f))) > installed]
                patched = min(newer, key=lambda f: tuple(map(int, re.findall(r"\d+", f))), default=None)
                try:
                    score = float(group.get("max_severity"))
                except (TypeError, ValueError):
                    score = None
                severity = "unrated" if score is None else "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "unrated"
                items.append({
                    "id": f"osv:{info['ecosystem']}/{name}@{version}:{group['ids'][0]}",
                    "source": "osv-scanner",
                    "severity": severity,
                    "title": vulns[0].get("summary") if vulns else f"{name} advisory",
                    "package": name,
                    "ecosystem": info["ecosystem"],
                    "manifest": (result.get("source") or {}).get("path"),
                    "patched_version": patched,
                    "advisory_ids": sorted({i.upper() for i in group["ids"] + (group.get("aliases") or [])}),
                    "url": None,
                    "action": "remediate-dependency" if patched else "manual-no-patch",
                    "links": [],
                })
    return items


def finding_text(finding):
    parts = [finding.get(k, "") for k in ("title", "description", "root_cause", "claimed_root_cause")]
    parts += [c.get("description", "") for c in finding.get("conditions") or []]
    parts += [t.get("description", "") for t in finding.get("trace") or []]
    return "\n".join(parts)


def stale_locations(finding, repo_root):
    """findings.json records no commit, so check every cited file:line still exists at this checkout."""
    stale = []
    for loc in (finding.get("trace") or []) + (finding.get("evidence") or []):
        path = (repo_root / loc["file"]).resolve()
        if repo_root not in path.parents or not path.is_file():
            stale.append(f"{loc['file']}:{loc['line']} (missing)")
            continue
        with open(path, "rb") as handle:
            if sum(1 for _ in handle) < loc["line"]:
                stale.append(f"{loc['file']}:{loc['line']} (past end of file)")
    return stale


def audit_items(findings, repo_root):
    items, dropped = [], 0
    for finding in findings:
        verdict = finding.get("verdict")
        if verdict == "rejected":
            dropped += 1
            continue
        stale = stale_locations(finding, repo_root) if repo_root else []
        if stale:
            action = "stale-reaudit"
        elif verdict == "confirmed":
            action = "remediate-code-finding"
        else:
            action = "validate-first"
        severity = (finding.get("severity") or {}).get("overall_severity", "informational")
        items.append({
            "id": f"audit:{finding['fingerprint']}",
            "source": "security-audit",
            "verdict": verdict,
            "severity": severity if verdict == "confirmed" else "unrated",
            "confidence": (finding.get("confidence") or {}).get("score"),
            "title": finding.get("title"),
            "advisory_ids": sorted({m.upper() for m in ADVISORY_ID.findall(finding_text(finding))}),
            "stale": stale,
            "action": action,
            "links": [],
        })
    return items, dropped


def link(dep_items, audit, texts):
    """Advisory-id match is strong evidence; a package-name mention is only a hint for a human."""
    for finding in audit:
        text = texts[finding["id"]].lower()
        for alert in dep_items:
            if set(finding["advisory_ids"]) & set(alert["advisory_ids"]):
                kind = "same-advisory"
            else:
                name = (alert["package"] or "").lower()
                if not name or not re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text):
                    continue
                kind = "mentions-package"
            alert["links"].append({"id": finding["id"], "kind": kind})
            finding["links"].append({"id": alert["id"], "kind": kind})


def rank_key(item):
    reachable = any(link["kind"] == "same-advisory" for link in item["links"])
    actionable = item["action"] in ("remediate-dependency", "remediate-code-finding")
    return (-actionable, -SEVERITY.get(item["severity"], -1), -reachable, item["id"])


def triage(dependabot=(), findings=(), repo_root=None, osv=()):
    root = Path(repo_root).resolve() if repo_root else None
    dep_items, dep_dropped = dependabot_items(dependabot)
    audit, audit_dropped = audit_items(findings, root)
    if isinstance(osv, dict):
        osv = osv.get("results") or []
    known = [(a["package"].lower(), set(a["advisory_ids"])) for a in dep_items if a["package"]]
    osv_all = osv_items(osv)
    osv_new = [o for o in osv_all if not any(o["package"].lower() == n and set(o["advisory_ids"]) & ids for n, ids in known)]
    dep_items += osv_new
    link(dep_items, audit, {f"audit:{f['fingerprint']}": finding_text(f) for f in findings})
    items = sorted(dep_items + audit, key=rank_key)
    return {"items": items, "dropped": {"dependabot_not_open": dep_dropped, "audit_rejected": audit_dropped,
                                           "osv_duplicate": len(osv_all) - len(osv_new)}}


def markdown(result):
    lines = ["| # | Severity | Action | Item | Links |", "|---|---|---|---|---|"]
    for n, item in enumerate(result["items"], 1):
        links = ", ".join(f"{link['id']} ({link['kind']})" for link in item["links"]) or "-"
        title = (item["title"] or "").replace("|", "\\|")
        lines.append(f"| {n} | {item['severity']} | {item['action']} | `{item['id']}` {title} | {links} |")
    dropped = result["dropped"]
    lines.append(f"\nDropped: {dropped['dependabot_not_open']} non-open alerts, {dropped['audit_rejected']} rejected findings, {dropped['osv_duplicate']} osv duplicates of Dependabot alerts.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependabot", type=Path, help="gh api --paginate --slurp repos/OWNER/REPO/dependabot/alerts output")
    parser.add_argument("--osv", type=Path, help="osv-scanner scan source -r --format json . output")
    parser.add_argument("--findings", type=Path, action="append", default=[], help="security-audit findings.json (repeatable)")
    parser.add_argument("--repo-root", type=Path, help="checkout the findings refer to; enables stale file:line checks")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    if not (args.dependabot or args.findings or args.osv):
        parser.error("give --dependabot, --findings and/or --osv")
    alerts = flatten(load_json(args.dependabot)) if args.dependabot else []
    findings = [f for path in args.findings for f in load_json(path)]
    osv = load_json(args.osv).get("results") or [] if args.osv else []
    result = triage(alerts, findings, args.repo_root, osv)
    print(markdown(result) if args.format == "markdown" else json.dumps(result, indent=2))


if __name__ == "__main__":
    sys.exit(main())
