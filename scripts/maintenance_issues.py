#!/usr/bin/env python3
"""Create, update, and verified-close deduplicated agent-actionable issues."""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Any


HEADINGS = [
    "Problem",
    "Scope",
    "Non-goals",
    "Acceptance",
    "Validation",
    "Dependencies",
    "Risk",
    "Rollout",
    "Observability",
    "Documentation",
    "Compatibility",
    "Generated artifacts",
    "Agent authorship",
]


def body(marker: str, values: dict[str, str], evidence_url: str) -> str:
    parts = [marker]
    for heading in HEADINGS:
        value = values[heading]
        parts.extend([f"### {heading}", "", value, ""])
    parts.extend(["### Latest automation evidence", "", evidence_url, ""])
    return "\n".join(parts)


def issue_spec(key: str, evidence_url: str) -> dict[str, Any]:
    marker = f"<!-- testament-maintenance:{key} -->"
    common = {
        "assignees": ["enoreyes"],
        "labels": ["maintenance", "agent-actionable"],
    }
    if key == "trademark-review":
        values = {
            "Problem": (
                "The 2026-08-21 USPTO and WIPO searches remain unresolved. The "
                "record supports qualified OSS repository use, not trademark clearance."
            ),
            "Scope": (
                "Preserve the naming evidence and obtain a dated, attestable "
                "qualified trademark review before commercial launch, filing, or "
                "broader distribution. The reviewer must be qualified trademark counsel."
            ),
            "Non-goals": (
                "This issue is non-blocking for the current open-source mission and "
                "does not declare the name unusable unless new evidence establishes that."
            ),
            "Acceptance": (
                "Attach dated qualified review covering relevant jurisdictions, "
                "classes, similar marks, and a reasoned disposition."
            ),
            "Validation": (
                "Reconcile policy/naming-clearance.json and public source links; "
                "record reviewer identity, scope, date, and conclusion."
            ),
            "Dependencies": "policy/naming-clearance.json and RES-STUDY-NAMING-001.",
            "Risk": (
                "Residual trademark risk is high for commercial launch or filing; "
                "current qualified OSS use remains conditionally approved."
            ),
            "Rollout": "Reopen before any trigger; do not close without attestable evidence.",
            "Observability": "Weekly automation updates this one marker-owned issue.",
            "Documentation": "Update the naming record and public research explanation.",
            "Compatibility": "No protocol compatibility impact.",
            "Generated artifacts": "No generated artifact is changed by issue automation.",
            "Agent authorship": "Automation maintains the record; @enoreyes owns disposition.",
        }
        return {
            **common,
            "title": "maintenance: qualified trademark review before commercial use",
            "body": body(marker, values, evidence_url),
        }
    if key == "single-maintainer-bootstrap":
        values = {
            "Problem": (
                "The foundation-process single-maintainer bootstrap exception expires "
                "on 2026-09-30."
            ),
            "Scope": (
                "Track the expiry while keeping the public sole-maintainer roster "
                "truthful. This record authorizes no access change and no appointment."
            ),
            "Non-goals": (
                "Do not grant repository access, appoint a maintainer, or extend the "
                "exception without a separately authorized governance decision."
            ),
            "Acceptance": (
                "Before 2026-09-30, record an authorized governance disposition. "
                "After expiry, stale bootstrap evidence receives zero readiness credit."
            ),
            "Validation": (
                "Compare MAINTAINERS.md, policy/governance-lifecycle.json, and remote "
                "direct collaborators without changing access."
            ),
            "Dependencies": "GOVERNANCE.md foundation-process bootstrap rules.",
            "Risk": "Expired exception evidence cannot support governance readiness.",
            "Rollout": "Keep open until a valid post-bootstrap governance record exists.",
            "Observability": "Weekly automation updates this one marker-owned issue.",
            "Documentation": "Keep sole-maintainer status and exception state public.",
            "Compatibility": "No protocol compatibility impact.",
            "Generated artifacts": "No generated artifact is changed by issue automation.",
            "Agent authorship": "Automation maintains the record; @enoreyes owns disposition.",
        }
        return {
            **common,
            "title": "maintenance: single-maintainer bootstrap expires 2026-09-30",
            "body": body(marker, values, evidence_url),
        }
    if key == "documentation-freshness":
        values = {
            "Problem": "Repository guidance and AGENTS evidence must remain fresh.",
            "Scope": "Track weekly documentation and agent-guidance freshness.",
            "Non-goals": "Do not rewrite accepted contracts through this issue.",
            "Acceptance": "The latest protected main run passes make agent-ready.",
            "Validation": "Run make agent-ready and inspect current public links.",
            "Dependencies": "AGENTS.md, docs/agent-guide.md, and docs/workflows.md.",
            "Risk": "Stale guidance can cause unsafe or non-reproducible agent work.",
            "Rollout": "Update or verified-close after the protected check passes.",
            "Observability": "Weekly automation updates this one marker-owned issue.",
            "Documentation": "The tracked surface is documentation.",
            "Compatibility": "No protocol compatibility impact.",
            "Generated artifacts": "Regenerate contract index when its sources change.",
            "Agent authorship": "Automation maintains the record; @enoreyes owns disposition.",
        }
        return {
            **common,
            "title": "maintenance: documentation and AGENTS freshness",
            "body": body(marker, values, evidence_url),
        }
    if key == "runtime-error":
        values = {
            "Problem": "A declared remote quality gate failed.",
            "Scope": "Track the stable Quality workflow failure and remediation evidence.",
            "Non-goals": "Do not weaken or bypass the failing Testament control.",
            "Acceptance": "The same protected workflow passes after the documented remediation.",
            "Validation": "Inspect the linked run, artifact, annotation, and corrected run.",
            "Dependencies": "Quality / gates and its machine-readable result artifact.",
            "Risk": "Unresolved failures invalidate affected readiness evidence.",
            "Rollout": "Close only after verified recovery from a passing Quality run.",
            "Observability": "Every recurrence updates this one marker-owned issue.",
            "Documentation": "Preserve the stable criterion and remediation link.",
            "Compatibility": "Depends on the failed gate; see linked evidence.",
            "Generated artifacts": "See the linked machine-readable quality artifact.",
            "Agent authorship": "Automation maintains the record; @enoreyes owns disposition.",
        }
        return {
            **common,
            "title": "maintenance: Quality workflow requires remediation",
            "body": body(marker, values, evidence_url),
        }
    raise ValueError(f"unknown maintenance key: {key}")


def find_existing(issues: list[dict[str, Any]], marker: str) -> dict[str, Any] | None:
    matches = [issue for issue in issues if marker in str(issue.get("body", ""))]
    if len(matches) > 1:
        raise RuntimeError(f"deduplication invariant failed for {marker}")
    return matches[0] if matches else None


def request(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request_value = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "testament-maintenance",
        },
    )
    with urllib.request.urlopen(request_value, timeout=30) as response:
        return json.load(response) if response.status != 204 else None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: maintenance_issues.py <record>", file=sys.stderr)
        return 2
    key = sys.argv[1]
    repository = os.environ["GH_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    evidence_url = os.environ.get("EVIDENCE_URL", "No run URL supplied")
    state = os.environ.get("MAINTENANCE_STATE", "open")
    verified = os.environ.get("VERIFIED_RECOVERY", "false") == "true"
    spec = issue_spec(key, evidence_url)
    marker = f"<!-- testament-maintenance:{key} -->"
    base = f"https://api.github.com/repos/{repository}"
    query = urllib.parse.urlencode({"state": "all", "per_page": 100})
    issues = request("GET", f"{base}/issues?{query}", token)
    existing = find_existing(
        [issue for issue in issues if "pull_request" not in issue],
        marker,
    )

    desired_state = "closed" if state == "close" and verified else "open"
    if existing:
        payload = {**spec, "state": desired_state}
        result = request("PATCH", f"{base}/issues/{existing['number']}", token, payload)
        operation = "updated"
    else:
        if desired_state == "closed":
            print(json.dumps({"status": "absent", "record": key}, sort_keys=True))
            return 0
        result = request("POST", f"{base}/issues", token, spec)
        operation = "created"
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criterion_id": "VAL-READY-028",
                "status": operation,
                "record": key,
                "issue_number": result["number"],
                "issue_state": result["state"],
                "url": result["html_url"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
