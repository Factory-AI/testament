#!/usr/bin/env python3
"""Validate Testament's foundational licensing and public claims policies."""

from __future__ import annotations

import argparse
from collections import Counter
import fnmatch
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_ARTIFACT_CLASSES = {
    "code",
    "dependencies",
    "generated",
    "documentation",
    "fixtures",
    "fonts",
    "notices",
}
REQUIRED_PUBLIC_DOCUMENTS = {
    "README.md",
    "CHARTER.md",
    "TERMINOLOGY.md",
    "docs/claims-policy.md",
    "docs/licensing.md",
    "LICENSE",
    "NOTICE",
}
APACHE_LICENSE_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
DEPENDENCY_FILES = {"Cargo.toml", "go.mod", "package.json", "requirements.txt"}
REQUIRED_SCAN_PATHS = {
    "README.md",
    "CHARTER.md",
    "TERMINOLOGY.md",
    "docs/*.md",
    "docs/**/*.md",
}
REQUIRED_LIMITATIONS = {
    "LIM-SAFETY-001": "No system can provide perfect safety.",
    "LIM-SEMANTICS-001": "Testament does not claim universal semantic understanding.",
    "LIM-RUNTIME-001": (
        "Application-layer encryption is not end-to-end protection against a compromised runtime."
    ),
    "LIM-ENFORCEMENT-001": "Testament does not automatically enforce decisions.",
    "LIM-CLOUD-001": (
        "Real GCP Cloud KMS and Azure Key Vault end-to-end conformance is unverified."
    ),
}
FORBIDDEN_CLAIMS = {
    "CLAIM-PERFECT-SAFETY": r"(?i)Testament guarantees perfect safety",
    "CLAIM-UNIVERSAL-SEMANTICS": r"(?i)Testament understands every model",
    "CLAIM-RUNTIME-E2E": (
        r"(?i)Testament is end-to-end encrypted against a compromised runtime"
    ),
    "CLAIM-AUTOMATIC-ENFORCEMENT": r"(?i)Testament automatically enforces",
    "CLAIM-UNVERIFIED-CLOUD": (
        r"(?i)Testament is verified on (GCP Cloud KMS|Azure Key Vault)"
    ),
}


def issue(criterion_id: str, code: str, path: str, message: str, command: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion_id,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": command,
    }


def load_json(
    root: Path,
    relative: str,
    criterion_id: str,
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    path = root / relative
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(
            issue(
                criterion_id,
                "invalid_json",
                relative,
                str(error),
                "make verify-foundation",
            )
        )
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(
                criterion_id,
                "invalid_policy_shape",
                relative,
                "Policy root must be a JSON object",
                f"repair {relative}",
            )
        )
        return {}
    return value


def require_list(
    value: Any,
    field: str,
    relative: str,
    criterion_id: str,
    problems: list[dict[str, str]],
) -> list[Any]:
    if isinstance(value, list):
        return value
    problems.append(
        issue(
            criterion_id,
            "invalid_policy_shape",
            relative,
            f"{field} must be an array",
            f"repair {field} in {relative}",
        )
    )
    return []


def validate_license(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/artifact-licensing.json"
    inventory = load_json(root, relative, "VAL-READY-002", problems)
    classes = require_list(
        inventory.get("artifact_classes"),
        "artifact_classes",
        relative,
        "VAL-READY-002",
        problems,
    )
    class_ids = [entry.get("id") for entry in classes if isinstance(entry, dict)]

    missing = sorted(REQUIRED_ARTIFACT_CLASSES - set(class_ids))
    duplicates = sorted(item for item, count in Counter(class_ids).items() if count > 1)
    if missing:
        problems.append(
            issue(
                "VAL-READY-002",
                "missing_artifact_class",
                relative,
                f"Missing licensing inventory classes: {', '.join(missing)}",
                "add each missing class to policy/artifact-licensing.json",
            )
        )
    if duplicates:
        problems.append(
            issue(
                "VAL-READY-002",
                "duplicate_artifact_class",
                relative,
                f"Duplicate licensing inventory classes: {', '.join(duplicates)}",
                "deduplicate policy/artifact-licensing.json",
            )
        )

    for entry in classes:
        if not isinstance(entry, dict):
            continue
        for field in ("id", "paths", "license", "notice_required", "current_status"):
            if field not in entry or entry[field] in ("", []):
                problems.append(
                    issue(
                        "VAL-READY-002",
                        "incomplete_inventory_entry",
                        relative,
                        f"Artifact class {entry.get('id', '<unknown>')} lacks {field}",
                        "complete the artifact class inventory entry",
                    )
                )

    dependency_policy = inventory.get("core_dependency_policy")
    if not isinstance(dependency_policy, dict):
        problems.append(
            issue(
                "VAL-READY-002",
                "invalid_policy_shape",
                relative,
                "core_dependency_policy must be an object",
                "repair core_dependency_policy in policy/artifact-licensing.json",
            )
        )
        dependency_policy = {}
    forbidden_entries = require_list(
        dependency_policy.get("forbidden"),
        "core_dependency_policy.forbidden",
        relative,
        "VAL-READY-002",
        problems,
    )
    forbidden = {item for item in forbidden_entries if isinstance(item, str)}
    expected_forbidden = {"AGPL-3.0", "Elastic-2.0", "GPL-3.0", "SSPL-1.0"}
    if not expected_forbidden.issubset(forbidden):
        problems.append(
            issue(
                "VAL-READY-002",
                "incomplete_forbidden_license_policy",
                relative,
                "Core policy must reject strong-copyleft, SSPL, and Elastic-2.0 dependencies",
                "restore the required forbidden license expressions",
            )
        )

    license_path = root / "LICENSE"
    try:
        license_digest = hashlib.sha256(license_path.read_bytes()).hexdigest()
    except OSError as error:
        problems.append(
            issue("VAL-READY-002", "missing_license", "LICENSE", str(error), "restore the Apache-2.0 LICENSE")
        )
    else:
        if license_digest != APACHE_LICENSE_SHA256:
            problems.append(
                issue(
                    "VAL-READY-002",
                    "invalid_project_license",
                    "LICENSE",
                    "LICENSE is not the canonical Apache License 2.0 text",
                    "restore the canonical Apache-2.0 LICENSE",
                )
            )

    dependencies = require_list(
        inventory.get("dependencies"),
        "dependencies",
        relative,
        "VAL-READY-002",
        problems,
    )
    manifests = sorted(path.name for path in (root / name for name in DEPENDENCY_FILES) if path.is_file())
    if manifests and not dependencies:
        problems.append(
            issue(
                "VAL-READY-002",
                "unaccounted_dependency_manifest",
                relative,
                f"Dependency manifests exist without inventory entries: {', '.join(manifests)}",
                "inventory every direct and transitive dependency with its SPDX expression",
            )
        )
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            problems.append(
                issue(
                    "VAL-READY-002",
                    "invalid_dependency_entry",
                    relative,
                    "Every dependency entry must be an object",
                    "repair the dependency inventory",
                )
            )
            continue
        for field in ("id", "version", "license", "usage", "manifest"):
            if not isinstance(dependency.get(field), str) or not dependency[field]:
                problems.append(
                    issue(
                        "VAL-READY-002",
                        "incomplete_dependency_entry",
                        relative,
                        f"Dependency {dependency.get('id', '<unknown>')} lacks {field}",
                        "complete the dependency inventory entry",
                    )
                )
        license_expression = str(dependency.get("license", ""))
        for token in forbidden:
            if token.lower() in license_expression.lower():
                problems.append(
                    issue(
                        "VAL-READY-002",
                        "forbidden_core_dependency",
                        relative,
                        f"Forbidden dependency license detected: {token}",
                        "remove or replace the forbidden dependency",
                    )
                )


def scan_files(root: Path, patterns: list[str]) -> list[Path]:
    paths: set[Path] = set()
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in patterns):
            paths.add(path)
    return sorted(paths)


def validate_claims(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/claims.json"
    policy = load_json(root, relative, "VAL-READY-003", problems)
    scan_paths = require_list(
        policy.get("scan_paths"),
        "scan_paths",
        relative,
        "VAL-READY-003",
        problems,
    )
    if set(scan_paths) != REQUIRED_SCAN_PATHS:
        problems.append(
            issue(
                "VAL-READY-003",
                "claims_scan_scope_changed",
                relative,
                "Claims scan paths must cover every public foundation document",
                "restore the required scan_paths in policy/claims.json",
            )
        )

    limitation_entries = require_list(
        policy.get("required_limitations"),
        "required_limitations",
        relative,
        "VAL-READY-003",
        problems,
    )
    declared_limitations = {
        entry.get("id"): entry.get("text")
        for entry in limitation_entries
        if isinstance(entry, dict)
    }
    if declared_limitations != REQUIRED_LIMITATIONS:
        problems.append(
            issue(
                "VAL-READY-003",
                "required_limitations_changed",
                relative,
                "Required limitation IDs or text differ from the validator trust anchor",
                "restore the required limitations in policy/claims.json",
            )
        )

    claim_entries = require_list(
        policy.get("forbidden_claims"),
        "forbidden_claims",
        relative,
        "VAL-READY-003",
        problems,
    )
    declared_claims = {
        entry.get("id"): entry.get("pattern")
        for entry in claim_entries
        if isinstance(entry, dict)
    }
    if declared_claims != FORBIDDEN_CLAIMS:
        problems.append(
            issue(
                "VAL-READY-003",
                "forbidden_claims_changed",
                relative,
                "Forbidden claim IDs or patterns differ from the validator trust anchor",
                "restore the forbidden claims in policy/claims.json",
            )
        )

    found_limitations: set[str] = set()
    found_claims: list[tuple[str, str, str]] = []
    for path in scan_files(root, sorted(REQUIRED_SCAN_PATHS)):
        text = path.read_text(encoding="utf-8")
        for limitation_id, limitation_text in REQUIRED_LIMITATIONS.items():
            if limitation_text in text:
                found_limitations.add(limitation_id)
        for claim_id, pattern in FORBIDDEN_CLAIMS.items():
            match = re.search(pattern, text)
            if match:
                found_claims.append((claim_id, path.relative_to(root).as_posix(), match.group(0)))

    for limitation_id, text in REQUIRED_LIMITATIONS.items():
        if limitation_id not in found_limitations:
            problems.append(
                issue(
                    "VAL-READY-003",
                    "missing_required_limitation",
                    relative,
                    f"{limitation_id}: {text}",
                    "restore the exact limitation in docs/claims-policy.md",
                )
            )

    for claim_id, claim_path, text in found_claims:
        problems.append(
            issue(
                "VAL-READY-003",
                "forbidden_claim",
                claim_path,
                f"{claim_id}: {text}",
                "remove the overclaim and state the supported limitation",
            )
        )


def validate_documents(root: Path, problems: list[dict[str, str]]) -> None:
    for relative in sorted(REQUIRED_PUBLIC_DOCUMENTS):
        path = root / relative
        try:
            missing = not path.is_file() or path.stat().st_size == 0
        except OSError:
            missing = True
        if missing:
            problems.append(
                issue(
                    "VAL-READY-003" if relative.endswith(".md") else "VAL-READY-002",
                    "missing_public_document",
                    relative,
                    "Required public foundation document is missing or empty",
                    f"restore {relative}",
                )
            )


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    validate_documents(root, problems)
    validate_license(root, problems)
    validate_claims(root, problems)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    problems = validate(root)
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criteria": ["VAL-READY-002", "VAL-READY-003"],
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
