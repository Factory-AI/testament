#!/usr/bin/env python3
"""Validate repository-scoped publication and remote workflow contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ISSUE_HEADINGS = [
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
PR_HEADINGS = ISSUE_HEADINGS.copy()
WORKFLOWS = {
    ".github/workflows/metadata.yml": ["issues:", "pull_request:"],
    ".github/workflows/dco.yml": ["pull_request:"],
    ".github/workflows/error-to-issue.yml": ["workflow_run:"],
    ".github/workflows/quality.yml": [
        "pull_request:",
        "push:",
        "schedule:",
        "workflow_dispatch:",
        "release:",
    ],
    ".github/workflows/security.yml": [
        "pull_request:",
        "push:",
        "schedule:",
        "workflow_dispatch:",
        "release:",
    ],
    ".github/workflows/maintenance.yml": ["schedule:", "workflow_dispatch:"],
}
REQUIRED_PATHS = [
    ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/work-item.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/dependabot.yml",
    *WORKFLOWS,
    "docs/remote-workflows.md",
    "policy/remote-workflows.json",
    "schemas/remote-workflows.schema.json",
    "scripts/check_dco.py",
    "scripts/maintenance_issues.py",
    "scripts/run_ci_gates.py",
    "scripts/verify_remote_workflows.py",
]
ACTION = re.compile(r"(?m)^\s*uses:\s+[^#\s]+@([^\s#]+)")
PIN = re.compile(r"^[0-9a-f]{40}$")
EMPTY = {"", "_none_", "none", "n/a", "not applicable", "tbd"}


def issue(code: str, path: str, message: str, command: str, criterion: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": command,
    }


def sections(body: str, level: int) -> dict[str, str]:
    pattern = re.compile(rf"(?m)^{'#' * level}\s+(.+?)\s*$")
    matches = list(pattern.finditer(body))
    values: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        content = body[match.end() : end]
        content = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL).strip()
        values[match.group(1).strip().casefold()] = content
    return values


def metadata_problems(kind: str, body: str) -> list[str]:
    headings = ISSUE_HEADINGS if kind == "issue" else PR_HEADINGS
    parsed = sections(body, 3 if kind == "issue" else 2)
    return [
        heading.casefold()
        for heading in headings
        if parsed.get(heading.casefold(), "").strip().casefold() in EMPTY
    ]


def scan_publication_paths(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    root = root.resolve()
    try:
        contract = json.loads(
            (root / "policy/remote-workflows.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        contract = {}
    allowlist = {
        (
            str(entry.get("code")),
            str(entry.get("path")),
            int(entry.get("line", 0)),
            str(entry.get("match_sha256")),
        )
        for entry in contract.get("publication_findings_allowlist", [])
        if isinstance(entry, dict)
    }
    patterns = [
        ("github_token", re.compile(("gh" + "[psuor]_" + r"[A-Za-z0-9]{36,}").encode())),
        (
            "private_key",
            re.compile(("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?" + "PRIVATE KEY-----").encode()),
        ),
        ("aws_access_key", re.compile(("AK" + "IA" + r"[A-Z0-9]{16}").encode())),
    ]
    findings: list[dict[str, str]] = []
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(f"publication path escapes repository root: {path}")
        if not resolved.is_file():
            continue
        data = resolved.read_bytes()
        relative = resolved.relative_to(root).as_posix()
        for code, pattern in patterns:
            for match in pattern.finditer(data):
                line = data.count(b"\n", 0, match.start()) + 1
                match_sha256 = hashlib.sha256(match.group()).hexdigest()
                if (code, relative, line, match_sha256) in allowlist:
                    continue
                findings.append(
                    {
                        "schema_version": "1.0.0",
                        "criterion_id": "VAL-READY-027",
                        "code": code,
                        "path": relative,
                        "line": str(line),
                        "message": "Potential secret found in Testament publication content",
                        "remediation_command": f"remove the finding from {relative} and rerun make verify-publication",
                    }
                )
    return findings


def unsigned_commits(commits: list[dict[str, Any]]) -> list[str]:
    signoff = re.compile(r"(?im)^Signed-off-by:\s+[^<\n]+<[^>\n]+>\s*$")
    return [
        str(commit["sha"])
        for commit in commits
        if not commit.get("grandfathered") and not signoff.search(str(commit["message"]))
    ]


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    for relative in REQUIRED_PATHS:
        if not (root / relative).is_file():
            problems.append(
                issue(
                    "missing_remote_workflow_path",
                    relative,
                    f"Required remote workflow path is missing: {relative}",
                    "restore the path and run make verify-remote-workflows",
                    "VAL-READY-027",
                )
            )
    try:
        contract = json.loads((root / "policy/remote-workflows.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        contract = {}
        problems.append(
            issue(
                "invalid_remote_workflow_contract",
                "policy/remote-workflows.json",
                str(error),
                "repair policy/remote-workflows.json",
                "VAL-READY-027",
            )
        )
    if contract.get("validation_ids") != [
        "VAL-READY-025",
        "VAL-READY-026",
        "VAL-READY-027",
        "VAL-READY-028",
    ]:
        problems.append(
            issue(
                "invalid_remote_workflow_contract",
                "policy/remote-workflows.json",
                "Remote workflow contract must own exactly VAL-READY-025 through 028",
                "restore the validation_ids list",
                "VAL-READY-027",
            )
        )

    for relative, triggers in WORKFLOWS.items():
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except OSError:
            continue
        for reference in ACTION.findall(text):
            if not PIN.fullmatch(reference):
                problems.append(
                    issue(
                        "unpinned_action",
                        relative,
                        f"Action reference is not an immutable commit: {reference}",
                        f"pin every action in {relative} to a reviewed 40-character commit",
                        "VAL-READY-027",
                    )
                )
        if "permissions: write-all" in text or "pull_request_target:" in text:
            problems.append(
                issue(
                    "excessive_workflow_permissions",
                    relative,
                    "Workflow uses write-all or pull_request_target",
                    f"restore least-privilege permissions in {relative}",
                    "VAL-READY-027",
                )
            )
        if any(trigger not in text for trigger in triggers):
            problems.append(
                issue(
                    "incomplete_workflow_triggers",
                    relative,
                    "Workflow lacks one or more required trigger classes",
                    f"restore required triggers in {relative}",
                    "VAL-READY-027",
                )
            )

    try:
        form = (root / ".github/ISSUE_TEMPLATE/work-item.yml").read_text(encoding="utf-8")
    except OSError:
        form = ""
    expected_ids = {
        "problem",
        "scope",
        "non_goals",
        "acceptance",
        "validation",
        "dependencies",
        "risk",
        "rollout",
        "observability",
        "documentation",
        "compatibility",
        "generated_artifacts",
        "agent_authorship",
    }
    actual_ids = set(re.findall(r"(?m)^\s+id:\s+([a-z_]+)\s*$", form))
    if actual_ids != expected_ids or form.count("required: true") < len(expected_ids):
        problems.append(
            issue(
                "incomplete_issue_form",
                ".github/ISSUE_TEMPLATE/work-item.yml",
                "Issue form does not require every stable actionable field",
                "restore all required fields and run make verify-remote-workflows",
                "VAL-READY-025",
            )
        )

    try:
        template = (root / ".github/PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    except OSError:
        template = ""
    if set(sections(template, 2)) != {heading.casefold() for heading in PR_HEADINGS}:
        problems.append(
            issue(
                "incomplete_pr_template",
                ".github/PULL_REQUEST_TEMPLATE.md",
                "Pull request template does not contain every stable actionable field once",
                "restore the PR template and run make verify-remote-workflows",
                "VAL-READY-025",
            )
        )

    try:
        owners = (root / ".github/CODEOWNERS").read_text(encoding="utf-8")
    except OSError:
        owners = ""
    if "* @enoreyes" not in owners or "/.github/CODEOWNERS @enoreyes" not in owners:
        problems.append(
            issue(
                "incomplete_codeowners",
                ".github/CODEOWNERS",
                "Repository and ownership policy lack the active maintainer",
                "restore CODEOWNERS from MAINTAINERS.md",
                "VAL-READY-026",
            )
        )
    return problems


def event_metadata(event_name: str, event_path: Path) -> int:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    kind = "issue" if event_name == "issues" else "pull_request"
    record = event["issue"] if kind == "issue" else event["pull_request"]
    missing = metadata_problems(kind, str(record.get("body") or ""))
    if not missing:
        print(json.dumps({"schema_version": "1.0.0", "criterion_id": "VAL-READY-025", "status": "passed", "kind": kind}, sort_keys=True))
        return 0
    problem = issue(
        "missing_actionable_metadata",
        f"{kind}#{record['number']}",
        f"Missing or empty stable sections: {', '.join(missing)}",
        f"edit {kind}#{record['number']} and complete every template section",
        "VAL-READY-025",
    )
    print(json.dumps(problem, sort_keys=True), file=sys.stderr)
    print(
        f"::error title=VAL-READY-025 metadata,file=.github/{'ISSUE_TEMPLATE/work-item.yml' if kind == 'issue' else 'PULL_REQUEST_TEMPLATE.md'}::"
        f"{problem['message']}; {problem['remediation_command']}",
        file=sys.stderr,
    )
    return 1


def publication_paths(root: Path, revision_range: str) -> list[Path]:
    output = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", revision_range],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [root / line for line in output.splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--event", choices=["issues", "pull_request"])
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--publication-range")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.event:
        if not arguments.event_path:
            parser.error("--event-path is required with --event")
        return event_metadata(arguments.event, arguments.event_path)
    problems = validate(root)
    if arguments.publication_range:
        try:
            paths = publication_paths(root, arguments.publication_range)
            problems.extend(scan_publication_paths(root, paths))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            problems.append(
                issue(
                    "publication_scope_failed",
                    ".",
                    str(error),
                    "run make verify-publication from the Testament repository root",
                    "VAL-READY-027",
                )
            )
    if problems:
        for problem in problems:
            print(json.dumps(problem, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criteria": [
                    "VAL-READY-025",
                    "VAL-READY-026",
                    "VAL-READY-027",
                    "VAL-READY-028",
                ],
                "status": "passed",
                "repository_root": ".",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
