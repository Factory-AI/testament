#!/usr/bin/env python3
"""Validate Testament's foundational licensing and public claims policies."""

from __future__ import annotations

import argparse
from collections import Counter
import fnmatch
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
import tomllib
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
DEPENDENCY_FILES = ("Cargo.toml", "go.mod", "package.json", "requirements.txt")
PACKAGE_DEPENDENCY_GROUPS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
CARGO_DEPENDENCY_GROUPS = ("dependencies", "dev-dependencies", "build-dependencies")
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


def dependency_record(manifest: str, dependency_id: str, version: str) -> tuple[str, str, str]:
    if not dependency_id or not version:
        raise ValueError("dependency identifiers and versions must be non-empty")
    return manifest, dependency_id, version


def cargo_version(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if not isinstance(value, dict):
        raise ValueError("Cargo dependency declarations must be strings or tables")
    version = value.get("version")
    if isinstance(version, str) and version:
        return version
    path = value.get("path")
    if isinstance(path, str) and path:
        return f"path:{path}"
    git = value.get("git")
    if isinstance(git, str) and git:
        revision = next(
            (
                value[field]
                for field in ("rev", "tag", "branch")
                if isinstance(value.get(field), str) and value[field]
            ),
            "",
        )
        return f"git:{git}{f'#{revision}' if revision else ''}"
    raise ValueError("Cargo dependency tables must declare version, path, or git")


def cargo_dependency(
    path: Path,
    dependency_id: str,
    value: Any,
    workspace_dependencies: dict[str, Any],
) -> tuple[str, str, str]:
    if not isinstance(dependency_id, str) or not dependency_id:
        raise ValueError("Cargo dependency identifiers must be non-empty strings")
    if isinstance(value, dict) and value.get("workspace") is True:
        try:
            value = workspace_dependencies[dependency_id]
        except KeyError as error:
            raise ValueError(
                f"Cargo workspace dependency {dependency_id} is not declared"
            ) from error
    package_id = (
        value.get("package", dependency_id)
        if isinstance(value, dict)
        else dependency_id
    )
    if not isinstance(package_id, str) or not package_id:
        raise ValueError("Cargo package identifiers must be non-empty strings")
    return dependency_record(path.name, package_id, cargo_version(value))


def cargo_dependencies(path: Path) -> list[tuple[str, str, str]]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    records: list[tuple[str, str, str]] = []
    workspace = document.get("workspace")
    if workspace is not None and not isinstance(workspace, dict):
        raise ValueError("Cargo workspace must be a table")
    workspace_dependencies = (
        workspace.get("dependencies", {}) if isinstance(workspace, dict) else {}
    )
    if not isinstance(workspace_dependencies, dict):
        raise ValueError("Cargo workspace dependencies must be a table")

    def collect(container: Any) -> None:
        if container is None:
            return
        if not isinstance(container, dict):
            raise ValueError("Cargo dependency group must be a table")
        for group in CARGO_DEPENDENCY_GROUPS:
            dependencies = container.get(group)
            if dependencies is None:
                continue
            if not isinstance(dependencies, dict):
                raise ValueError(f"Cargo {group} must be a table")
            records.extend(
                cargo_dependency(
                    path,
                    dependency_id,
                    value,
                    workspace_dependencies,
                )
                for dependency_id, value in dependencies.items()
            )

    collect(document)
    if workspace is not None:
        collect(workspace)
    targets = document.get("target")
    if targets is not None:
        if not isinstance(targets, dict):
            raise ValueError("Cargo target must be a table")
        for target in targets.values():
            collect(target)
    return records


def go_dependencies(path: Path) -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    in_require_block = False
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if in_require_block:
            if line == ")":
                in_require_block = False
                continue
            tokens = shlex.split(line)
        elif line == "require (":
            in_require_block = True
            continue
        elif line.startswith("require "):
            tokens = shlex.split(line[len("require ") :])
        else:
            continue
        if len(tokens) != 2:
            raise ValueError(f"invalid go.mod require declaration on line {line_number}")
        records.append(dependency_record(path.name, tokens[0], tokens[1]))
    if in_require_block:
        raise ValueError("unterminated go.mod require block")
    return records


def package_dependencies(path: Path) -> list[tuple[str, str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("package.json root must be an object")
    records: list[tuple[str, str, str]] = []
    for group in PACKAGE_DEPENDENCY_GROUPS:
        dependencies = document.get(group)
        if dependencies is None:
            continue
        if not isinstance(dependencies, dict):
            raise ValueError(f"package.json {group} must be an object")
        for dependency_id, version in dependencies.items():
            if not isinstance(dependency_id, str) or not isinstance(version, str):
                raise ValueError(f"package.json {group} entries must be string pairs")
            records.append(dependency_record(path.name, dependency_id, version))
    return records


def requirement_dependencies(path: Path) -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            raise ValueError(
                f"unsupported requirements.txt directive on line {line_number}"
            )
        declaration = line.split(";", 1)[0].strip()
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(.*)",
            declaration,
        )
        if not match:
            raise ValueError(
                f"invalid requirements.txt declaration on line {line_number}"
            )
        dependency_id, version = match.groups()
        version = version.strip()
        if version.startswith("@"):
            source = version[1:].strip()
            if not source or any(character.isspace() for character in source):
                raise ValueError(
                    f"invalid requirements.txt direct reference on line {line_number}"
                )
            version = f"@ {source}"
        elif version:
            specifier = re.compile(
                r"(?:===|~=|==|!=|<=|>=|<|>)"
                r"\s*[A-Za-z0-9][A-Za-z0-9.*+!_-]*"
            )
            if not re.fullmatch(
                rf"{specifier.pattern}(?:\s*,\s*{specifier.pattern})*",
                version,
            ):
                raise ValueError(
                    f"invalid requirements.txt version on line {line_number}"
                )
            version = re.sub(r"\s+", "", version)
            if version.startswith("==") and "," not in version:
                version = version[2:]
        records.append(dependency_record(path.name, dependency_id, version or "*"))
    return records


def declared_dependencies(
    root: Path, problems: list[dict[str, str]]
) -> list[tuple[str, str, str]]:
    parsers = {
        "Cargo.toml": cargo_dependencies,
        "go.mod": go_dependencies,
        "package.json": package_dependencies,
        "requirements.txt": requirement_dependencies,
    }
    records: list[tuple[str, str, str]] = []
    for manifest in DEPENDENCY_FILES:
        path = root / manifest
        if not path.is_file():
            continue
        try:
            records.extend(parsers[manifest](path))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
            problems.append(
                issue(
                    "VAL-READY-002",
                    "invalid_dependency_manifest",
                    manifest,
                    str(error),
                    f"repair {manifest} and rerun make verify-foundation",
                )
            )
    return sorted(set(records))


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
    manifest_dependencies = declared_dependencies(root, problems)
    manifests = sorted({record[0] for record in manifest_dependencies})
    if manifest_dependencies and not dependencies:
        problems.append(
            issue(
                "VAL-READY-002",
                "unaccounted_dependency_manifest",
                relative,
                f"Dependency manifests exist without inventory entries: {', '.join(manifests)}",
                "inventory every direct and transitive dependency with its SPDX expression",
            )
        )
    inventory_records: set[tuple[str, str, str]] = set()
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
        if all(
            isinstance(dependency.get(field), str) and dependency[field]
            for field in ("id", "version", "manifest")
        ):
            inventory_records.add(
                (
                    dependency["manifest"],
                    dependency["id"],
                    dependency["version"],
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

    for manifest, dependency_id, version in manifest_dependencies:
        if (manifest, dependency_id, version) not in inventory_records:
            problems.append(
                issue(
                    "VAL-READY-002",
                    "missing_dependency_inventory_entry",
                    manifest,
                    f"Dependency {dependency_id}@{version} declared in {manifest} "
                    "is missing from the licensing inventory",
                    "add the dependency with its exact manifest, version, usage, "
                    "and SPDX license to policy/artifact-licensing.json",
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
