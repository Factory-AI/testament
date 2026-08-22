#!/usr/bin/env python3
"""Validate Testament governance, security, contribution, RFC, and ADR lifecycles."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


CRITERIA = ["VAL-READY-004", "VAL-READY-005"]
PUBLIC_DOCUMENTS = {
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/governance-sources.md",
    "docs/rfcs/README.md",
    "docs/rfcs/TEMPLATE.md",
    "docs/rfcs/index.json",
    "docs/adrs/README.md",
    "docs/adrs/TEMPLATE.md",
    "docs/adrs/index.json",
    "policy/governance-lifecycle.json",
}
STATUSES = {"proposed", "in-review", "accepted", "rejected", "withdrawn", "superseded"}
MAX_RECORD_BYTES = 512 * 1024
REQUIRED_MANIFEST_SECTIONS = {
    "maintainer_authority",
    "decision_process",
    "appeal_process",
    "release_authority",
    "maintenance_cadence",
    "security_reporting",
    "contribution_process",
    "rfc_lifecycle",
    "adr_lifecycle",
}
REQUIRED_TEMPLATE_HEADINGS = {
    "rfc": {
        "## Summary",
        "## Motivation",
        "## Scope and non-goals",
        "## Proposed contract",
        "## Compatibility and migration",
        "## Security and privacy",
        "## Alternatives",
        "## Validation",
        "## Decision",
        "## Supersession",
    },
    "adr": {
        "## Context",
        "## Decision",
        "## Alternatives",
        "## Compatibility",
        "## Security and privacy",
        "## Consequences",
        "## Validation",
        "## Supersession",
    },
}


def issue(criterion: str, code: str, path: str, message: str, command: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": command,
    }


def load_json(root: Path, relative: str, problems: list[dict[str, str]]) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(issue(CRITERIA[-1], "invalid_json", relative, str(error), "make verify-governance"))
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(CRITERIA[-1], "invalid_json_shape", relative, "Root must be an object", "make verify-governance")
        )
        return {}
    return value


def parse_record_header(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines()[:16]:
        match = re.fullmatch(r"([A-Za-z][A-Za-z ]+):\s+(.+)", line)
        if match:
            values[match.group(1).lower().replace(" ", "_")] = match.group(2)
    return values


def validate_manifest(root: Path, problems: list[dict[str, str]]) -> int:
    relative = "policy/governance-lifecycle.json"
    manifest = load_json(root, relative, problems)
    if manifest.get("schema_version") != "1.0.0":
        problems.append(
            issue(CRITERIA[0], "invalid_manifest_version", relative, "schema_version must be 1.0.0", "repair the manifest")
        )
    if manifest.get("validation_ids") != CRITERIA:
        problems.append(
            issue(
                CRITERIA[0],
                "validation_scope_drift",
                relative,
                f"validation_ids must equal {CRITERIA!r}",
                "restore the assigned validation IDs",
            )
        )
    sections = manifest.get("sections")
    if not isinstance(sections, dict):
        sections = {}
    missing = sorted(REQUIRED_MANIFEST_SECTIONS - set(sections))
    if missing:
        problems.append(
            issue(
                CRITERIA[0],
                "missing_lifecycle_section",
                relative,
                f"Missing lifecycle sections: {', '.join(missing)}",
                "complete policy/governance-lifecycle.json",
            )
        )
    for section_id, section in sections.items():
        if not isinstance(section, dict):
            continue
        for field in ("document", "owner", "machine_check", "manual_observation"):
            if not section.get(field):
                problems.append(
                    issue(
                        CRITERIA[0],
                        "incomplete_lifecycle_section",
                        relative,
                        f"{section_id} lacks {field}",
                        "complete the lifecycle section",
                    )
                )
        document = section.get("document")
        if isinstance(document, str) and not (root / document).is_file():
            problems.append(
                issue(
                    CRITERIA[0],
                    "missing_section_document",
                    relative,
                    f"{section_id} references missing {document}",
                    f"restore {document}",
                )
            )
    reporting = manifest.get("private_vulnerability_reporting")
    expected_reporting = {
        "repository": "Factory-AI/testament",
        "enabled": True,
        "evidence_kind": "manual_remote_observation",
        "verification_command": "gh api repos/Factory-AI/testament/private-vulnerability-reporting",
        "report_url": "https://github.com/Factory-AI/testament/security/advisories",
        "observed_response": {"enabled": True},
    }
    if not isinstance(reporting, dict):
        reporting = {}
    for field, expected in expected_reporting.items():
        if reporting.get(field) != expected:
            problems.append(
                issue(
                    CRITERIA[0],
                    "private_reporting_evidence_invalid",
                    relative,
                    f"{field} must equal {expected!r}",
                    "re-run the recorded GitHub verification command and reconcile the evidence",
                )
            )
    verified_at = reporting.get("verified_at")
    if not isinstance(verified_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", verified_at):
        problems.append(
            issue(
                CRITERIA[0],
                "private_reporting_not_verified",
                relative,
                "GitHub private vulnerability reporting needs a dated manual remote observation",
                "gh api repos/Factory-AI/testament/private-vulnerability-reporting",
            )
        )
    maintainers = manifest.get("maintainers")
    if not isinstance(maintainers, list):
        maintainers = []
    active_roles: set[str] = set()
    active_maintainer_count = 0
    for maintainer in maintainers:
        if not isinstance(maintainer, dict):
            continue
        if maintainer.get("status") == "active":
            active_maintainer_count += 1
            roles = maintainer.get("roles", [])
            if isinstance(roles, list):
                active_roles.update(str(role) for role in roles)
        for field in ("name", "github", "status", "since", "roles"):
            if not maintainer.get(field):
                problems.append(
                    issue(CRITERIA[0], "incomplete_maintainer", relative, f"Maintainer lacks {field}", "repair roster")
                )
    for role in ("lead", "release", "security"):
        if role not in active_roles:
            problems.append(
                issue(CRITERIA[0], "missing_maintainer_role", relative, f"No active {role} maintainer", "appoint the role")
            )
    roster_path = root / "MAINTAINERS.md"
    if roster_path.is_file():
        roster = roster_path.read_text(encoding="utf-8")
        for maintainer in maintainers:
            if not isinstance(maintainer, dict) or maintainer.get("status") != "active":
                continue
            github = maintainer.get("github")
            if isinstance(github, str) and f"@{github}" not in roster:
                problems.append(
                    issue(
                        CRITERIA[0],
                        "maintainer_roster_drift",
                        "MAINTAINERS.md",
                        f"Active maintainer @{github} is absent from the public roster",
                        "reconcile MAINTAINERS.md and policy/governance-lifecycle.json",
                    )
                )
    return active_maintainer_count


def validate_public_documents(root: Path, problems: list[dict[str, str]]) -> None:
    for relative in sorted(PUBLIC_DOCUMENTS):
        path = root / relative
        if not path.is_file() or path.stat().st_size == 0:
            problems.append(
                issue(CRITERIA[0], "missing_public_document", relative, "Required document is absent", f"restore {relative}")
            )

    requirements = {
        "GOVERNANCE.md": [
            "## Maintainer authority",
            "## Decisions and quorum",
            "## Conflicts of interest",
            "## Escalation and appeals",
            "## Amendments",
            "## Release authority",
        ],
        "SECURITY.md": [
            "## Supported versions",
            "## Private reporting",
            "## Response expectations",
            "## Coordinated disclosure",
            "## Safe harbor",
            "## Emergency escalation",
        ],
        "CONTRIBUTING.md": [
            "## Legal sign-off",
            "Signed-off-by:",
            "git commit -s",
            "## Branch and commit rules",
            "## Tests and validation",
            "## Documentation",
            "## Generated files",
            "## Review",
        ],
    }
    for relative, needles in requirements.items():
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                problems.append(
                    issue(
                        CRITERIA[0] if relative != "CONTRIBUTING.md" else CRITERIA[1],
                        "missing_required_process",
                        relative,
                        f"Missing required text: {needle}",
                        f"complete {relative}",
                    )
                )


def validate_index(
    root: Path,
    kind: str,
    active_maintainer_count: int,
    problems: list[dict[str, str]],
) -> None:
    directory = f"docs/{kind}s"
    relative = f"{directory}/index.json"
    index = load_json(root, relative, problems)
    if index.get("schema_version") != "1.0.0":
        problems.append(issue(CRITERIA[1], "invalid_index_version", relative, "schema_version must be 1.0.0", "repair the index"))
    if index.get("record_type") != kind:
        problems.append(issue(CRITERIA[1], "invalid_record_type", relative, f"record_type must be {kind}", "repair the index"))
    declared_statuses = index.get("statuses")
    if (
        not isinstance(declared_statuses, list)
        or not all(isinstance(status, str) for status in declared_statuses)
        or set(declared_statuses) != STATUSES
        or len(declared_statuses) != len(STATUSES)
    ):
        problems.append(
            issue(
                CRITERIA[1],
                "invalid_status_registry",
                relative,
                "statuses must contain each controlled status exactly once",
                "restore the controlled status registry",
            )
        )
    records = index.get("records")
    if not isinstance(records, list):
        records = []
        problems.append(issue(CRITERIA[1], "invalid_index", relative, "records must be an array", "repair the index"))
    ids = [
        record.get("id")
        for record in records
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    ]
    for duplicate, count in Counter(ids).items():
        if duplicate and count > 1:
            problems.append(
                issue(CRITERIA[1], "duplicate_record_id", relative, f"Duplicate ID {duplicate}", "deduplicate the index")
            )

    expected_prefix = kind.upper() + "-"
    by_id = {
        record["id"]: record
        for record in records
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }
    indexed_paths: set[str] = set()
    accepted = 0
    superseded = 0
    for record in records:
        if not isinstance(record, dict):
            problems.append(
                issue(CRITERIA[1], "invalid_record_entry", relative, "Every record must be an object", "repair the index")
            )
            continue
        record_id = record.get("id")
        path_value = record.get("path")
        status = record.get("status")
        if not isinstance(record_id, str) or not re.fullmatch(expected_prefix + r"\d{4}", record_id):
            problems.append(issue(CRITERIA[1], "invalid_record_id", relative, str(record_id), "repair the record ID"))
            continue
        if not isinstance(status, str) or status not in STATUSES:
            problems.append(
                issue(CRITERIA[1], "invalid_record_status", relative, f"{record_id}: {status}", "use a controlled status")
            )
        accepted += status == "accepted"
        superseded += status == "superseded"
        record_path = Path(path_value) if isinstance(path_value, str) else None
        if (
            record_path is None
            or record_path.is_absolute()
            or record_path.parent != Path(directory)
            or ".." in record_path.parts
        ):
            problems.append(issue(CRITERIA[1], "invalid_record_path", relative, record_id, "repair the record path"))
            continue
        indexed_paths.add(path_value)
        path = root / path_value
        if not path.is_file():
            problems.append(issue(CRITERIA[1], "missing_record", path_value, record_id, "restore the indexed record"))
            continue
        if path.stat().st_size > MAX_RECORD_BYTES:
            problems.append(
                issue(
                    CRITERIA[1],
                    "record_too_large",
                    path_value,
                    f"Record exceeds the {MAX_RECORD_BYTES}-byte validation budget",
                    "split supporting material from the decision record",
                )
            )
            continue
        try:
            content = path.read_bytes()
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            problems.append(
                issue(CRITERIA[1], "unreadable_record", path_value, str(error), "restore a readable UTF-8 record")
            )
            continue
        digest = hashlib.sha256(content).hexdigest()
        if digest != record.get("sha256"):
            problems.append(
                issue(
                    CRITERIA[1],
                    "immutable_record_changed",
                    path_value,
                    f"{record_id} digest does not match its index",
                    f"restore {path_value}; substantive changes require a superseding record",
                )
            )
        header = parse_record_header(text)
        expected_header = {
            "id": record_id,
            "status": record.get("record_status", status),
            "version": record.get("version"),
            "supersedes": record.get("record_supersedes") or "None",
            "superseded_by": record.get("record_superseded_by") or "None",
        }
        for field, expected in expected_header.items():
            if header.get(field) != expected:
                problems.append(
                    issue(
                        CRITERIA[1],
                        "record_index_drift",
                        path_value,
                        f"{field} is {header.get(field)!r}, expected {expected!r}",
                        "reconcile the record and index",
                    )
                )
        required = REQUIRED_TEMPLATE_HEADINGS[kind]
        for heading in required:
            if heading not in text:
                problems.append(
                    issue(CRITERIA[1], "incomplete_record", path_value, f"Missing {heading}", "complete the record")
                )
        if isinstance(status, str) and status in {"accepted", "superseded"}:
            for field in ("decision_date", "deciders"):
                if not record.get(field):
                    problems.append(
                        issue(CRITERIA[1], "missing_decision_metadata", relative, f"{record_id} lacks {field}", "repair the index")
                    )
            bootstrap_exception = record.get("bootstrap_exception", False)
            reviewers = record.get("reviewers")
            if bootstrap_exception is True:
                expiry_value = record.get("bootstrap_expiry")
                try:
                    expiry = date.fromisoformat(expiry_value) if isinstance(expiry_value, str) else None
                except ValueError:
                    expiry = None
                if (
                    reviewers != []
                    or not record.get("bootstrap_rationale")
                    or expiry is None
                    or expiry <= date.today()
                    or active_maintainer_count != 1
                    or record.get("bootstrap_scope") != "foundation-process"
                ):
                    problems.append(
                        issue(
                            CRITERIA[1],
                            "invalid_bootstrap_exception",
                            relative,
                            f"{record_id} must have one active maintainer, no reviewer, foundation-process scope, rationale, and a future ISO expiry",
                            "repair the bounded bootstrap exception",
                        )
                    )
            elif not reviewers:
                problems.append(
                    issue(CRITERIA[1], "missing_decision_metadata", relative, f"{record_id} lacks reviewers", "repair the index")
                )
        replacement_value = record.get("superseded_by")
        replacement_id = replacement_value if isinstance(replacement_value, str) else None
        if replacement_value is not None and not replacement_id:
            problems.append(
                issue(CRITERIA[1], "invalid_supersession_id", relative, f"{record_id} has invalid superseded_by", "repair the index")
            )
        if status == "superseded" and not replacement_id:
            problems.append(
                issue(CRITERIA[1], "missing_supersession", relative, f"{record_id} lacks superseded_by", "link its successor")
            )
        if replacement_id:
            replacement = by_id.get(replacement_id)
            if (
                not replacement
                or replacement.get("supersedes") != record_id
                or replacement.get("status") != "accepted"
            ):
                problems.append(
                    issue(CRITERIA[1], "broken_supersession", relative, f"{record_id} -> {replacement_id}", "repair both links")
                )
        predecessor_value = record.get("supersedes")
        predecessor_id = predecessor_value if isinstance(predecessor_value, str) else None
        if predecessor_value is not None and not predecessor_id:
            problems.append(
                issue(CRITERIA[1], "invalid_supersession_id", relative, f"{record_id} has invalid supersedes", "repair the index")
            )
        if predecessor_id:
            if record.get("record_supersedes") != predecessor_id:
                problems.append(
                    issue(
                        CRITERIA[1],
                        "mutable_lineage_mismatch",
                        relative,
                        f"{record_id} index lineage differs from its immutable successor header",
                        "restore supersedes from record_supersedes",
                    )
                )
            predecessor = by_id.get(predecessor_id)
            if (
                not predecessor
                or predecessor.get("superseded_by") != record_id
                or predecessor.get("status") != "superseded"
            ):
                problems.append(
                    issue(CRITERIA[1], "broken_supersession", relative, f"{record_id} <- {predecessor_id}", "repair both links")
                )

    for path in (root / directory).glob("[0-9][0-9][0-9][0-9]-*.md"):
        path_value = path.relative_to(root).as_posix()
        if path_value not in indexed_paths:
            problems.append(issue(CRITERIA[1], "orphaned_record", path_value, "Record is not indexed", "add it to the index"))
    if not accepted:
        problems.append(issue(CRITERIA[1], "missing_accepted_example", relative, f"No accepted {kind}", "add an accepted example"))
    if not superseded:
        problems.append(
            issue(CRITERIA[1], "missing_superseded_example", relative, f"No superseded {kind}", "add a superseded example")
        )


def validate_templates(root: Path, problems: list[dict[str, str]]) -> None:
    for kind, headings in REQUIRED_TEMPLATE_HEADINGS.items():
        relative = f"docs/{kind}s/TEMPLATE.md"
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for heading in headings:
            if heading not in text:
                problems.append(
                    issue(CRITERIA[1], "incomplete_template", relative, f"Missing {heading}", "complete the template")
                )


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    validate_public_documents(root, problems)
    active_maintainer_count = validate_manifest(root, problems)
    validate_templates(root, problems)
    validate_index(root, "rfc", active_maintainer_count, problems)
    validate_index(root, "adr", active_maintainer_count, problems)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    problems = validate(args.root.resolve())
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criteria": CRITERIA,
                "status": "pass" if not problems else "fail",
                "problems": problems,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
