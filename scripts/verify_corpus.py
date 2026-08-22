#!/usr/bin/env python3
"""Verify safety, licensing, completeness, and byte reproducibility of the corpus."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MANIFEST_PATH = "docs/research/corpus/manifest.json"
SCHEMA_PATH = "schemas/synthetic-corpus.schema.json"
GENERATOR_PATH = "scripts/generate_corpus.py"
FIXTURE_ROOT = "fixtures/research-corpus"
CRITERIA = ["VAL-READY-012", "VAL-READY-013"]
REQUIRED_CLASSES = {
    "provider",
    "giant",
    "malformed",
    "stream",
    "tool",
    "retry",
    "multimodal",
    "late",
    "missing-lineage",
    "authorized-twin",
    "abuse",
}
REQUIRED_PROVIDERS = {"openai", "anthropic", "gemini", "bedrock"}
ALLOWED_LICENSES = {"Apache-2.0"}
MAX_FIXTURE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
SECRET_PATTERNS = {
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_password": re.compile(rb"(?i)(?:password|passwd)\s*[:=]\s*[^\s,;]{4,}"),
    "openai_key": re.compile(rb"sk-[A-Za-z0-9]{20,}"),
}
PII_PATTERNS = {
    "email": re.compile(
        rb"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"
        rb"@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}"
    ),
    "ipv4": re.compile(
        rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
    ),
    "us_ssn": re.compile(rb"(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])"),
}


def load_generator():
    path = Path(__file__).resolve().parent / "generate_corpus.py"
    spec = importlib.util.spec_from_file_location("generate_corpus", path)
    if not spec or not spec.loader:
        raise RuntimeError("cannot load corpus generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_generator()
CORPUS_FILES = {
    ".gitattributes",
    MANIFEST_PATH,
    SCHEMA_PATH,
    GENERATOR_PATH,
    "policy/research-manifest.json",
    "scripts/verify_research.py",
    "scripts/verify_corpus.py",
    *(
        f"{FIXTURE_ROOT}/{definition['file']}"
        for definition in GENERATOR.FIXTURES
    ),
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


def canonical(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def semver(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        return None
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def load_manifest(root: Path, problems: list[dict[str, str]]) -> dict[str, Any]:
    try:
        value = json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(
            issue(CRITERIA[0], "invalid_corpus_manifest", MANIFEST_PATH, str(error), "make generate-corpus")
        )
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(CRITERIA[0], "invalid_corpus_manifest", MANIFEST_PATH, "Root must be an object", "make generate-corpus")
        )
        return {}
    return value


def validate_schema(
    root: Path, manifest: dict[str, Any], problems: list[dict[str, str]]
) -> None:
    try:
        schema = json.loads((root / SCHEMA_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(
            issue(CRITERIA[0], "invalid_corpus_schema", SCHEMA_PATH, str(error), "restore the corpus schema")
        )
        return
    validator_path = root / "scripts/verify_research.py"
    spec = importlib.util.spec_from_file_location("research_schema_validator", validator_path)
    if not spec or not spec.loader:
        problems.append(
            issue(CRITERIA[0], "invalid_corpus_schema", SCHEMA_PATH, "Cannot load schema validator", "restore scripts/verify_research.py")
        )
        return
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    for message in validator.schema_errors(manifest, schema, schema):
        problems.append(
            issue(
                CRITERIA[0],
                "corpus_schema_validation_failed",
                MANIFEST_PATH,
                message,
                "make generate-corpus",
            )
        )


def synchronized_change_problems(
    previous: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    changed_fixture_ids: list[str] = []
    old_by_id = {
        item.get("id"): item
        for item in previous.get("fixtures", [])
        if isinstance(item, dict)
    }
    for fixture in current.get("fixtures", []):
        if not isinstance(fixture, dict):
            continue
        old = old_by_id.get(fixture.get("id"))
        if not isinstance(old, dict) or old.get("sha256") == fixture.get("sha256"):
            continue
        changed_fixture_ids.append(str(fixture.get("id")))
        old_version = semver(old.get("version"))
        new_version = semver(fixture.get("version"))
        changed = {
            "version": bool(old_version and new_version and new_version > old_version),
            "provenance": canonical(old.get("provenance")) != canonical(fixture.get("provenance")),
            "expectations": canonical(old.get("expectations")) != canonical(fixture.get("expectations")),
        }
        missing = sorted(field for field, updated in changed.items() if not updated)
        if missing:
            failures.append(f"{fixture.get('id')}: {', '.join(missing)}")
    if changed_fixture_ids:
        old_version = semver(previous.get("version"))
        new_version = semver(current.get("version"))
        if not old_version or not new_version or new_version <= old_version:
            failures.append(
                f"corpus version did not advance for: {', '.join(changed_fixture_ids)}"
            )
    return failures


def git_manifest(root: Path, revision: str) -> dict[str, Any] | None:
    completed = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{MANIFEST_PATH}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def validate_history(
    root: Path, manifest: dict[str, Any], problems: list[dict[str, str]]
) -> None:
    baseline = git_manifest(root, "HEAD")
    if baseline == manifest:
        baseline = git_manifest(root, "HEAD^")
    if not baseline:
        return
    failures = synchronized_change_problems(baseline, manifest)
    if failures:
        problems.append(
            issue(
                CRITERIA[1],
                "unsynchronized_fixture_change",
                MANIFEST_PATH,
                "; ".join(failures),
                "increase corpus and fixture versions and update provenance and expectations with the changed generator recipe",
            )
        )


def validate_registry_version(
    root: Path, manifest: dict[str, Any], problems: list[dict[str, str]]
) -> None:
    relative = "policy/research-manifest.json"
    try:
        registry = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(
            issue(CRITERIA[0], "invalid_research_registry", relative, str(error), "make verify-research")
        )
        return
    records = registry.get("deliverables", []) if isinstance(registry, dict) else []
    matches = [
        record
        for record in records
        if isinstance(record, dict)
        and record.get("id") == "RES-CORPUS-SYNTHETIC-TRACE-001"
    ]
    if len(matches) != 1:
        problems.append(
            issue(CRITERIA[0], "missing_corpus_registry_entry", relative, f"found {len(matches)} entries", "repair the research registry")
        )
        return
    record = matches[0]
    if (
        record.get("version") != manifest.get("version")
        or record.get("artifact", {}).get("path") != MANIFEST_PATH
        or record.get("state") not in {"draft", "in-review"}
    ):
        problems.append(
            issue(
                CRITERIA[0],
                "corpus_registry_drift",
                relative,
                "Corpus version, artifact path, or lifecycle state disagrees with the corpus manifest",
                "synchronize the corpus registry entry with the corpus manifest",
            )
        )


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    manifest = load_manifest(root, problems)
    validate_schema(root, manifest, problems)
    validate_registry_version(root, manifest, problems)
    attributes_path = root / ".gitattributes"
    try:
        attributes = attributes_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        problems.append(
            issue(CRITERIA[1], "missing_fixture_git_attributes", ".gitattributes", str(error), "restore binary fixture attributes")
        )
    else:
        if "fixtures/research-corpus/** binary" not in attributes:
            problems.append(
                issue(
                    CRITERIA[1],
                    "missing_fixture_git_attributes",
                    ".gitattributes",
                    "Research fixtures must be byte-preserved as Git binary content",
                    "add 'fixtures/research-corpus/** binary' to .gitattributes",
                )
            )
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("deliverable_id") != "RES-CORPUS-SYNTHETIC-TRACE-001"
        or manifest.get("feature_id") != "synthetic-corpus-and-reproducibility"
        or manifest.get("validation_ids") != CRITERIA
        or manifest.get("status") != "informative-research"
        or semver(manifest.get("version")) is None
    ):
        problems.append(
            issue(
                CRITERIA[0],
                "invalid_corpus_identity",
                MANIFEST_PATH,
                "Corpus identity, validation scope, status, or version drifted",
                "make generate-corpus",
            )
        )
    fixtures = manifest.get("fixtures")
    records = fixtures if isinstance(fixtures, list) else []
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    duplicates = sorted(value for value, count in Counter(ids).items() if value and count > 1)
    if duplicates:
        problems.append(
            issue(CRITERIA[0], "duplicate_fixture_id", MANIFEST_PATH, ", ".join(duplicates), "deduplicate fixture IDs")
        )
    classes = {
        fixture_class
        for record in records
        if isinstance(record, dict)
        for fixture_class in record.get("classes", [])
        if isinstance(fixture_class, str)
    }
    missing_classes = sorted(REQUIRED_CLASSES - classes)
    if missing_classes:
        problems.append(
            issue(
                CRITERIA[0],
                "missing_fixture_class",
                MANIFEST_PATH,
                ", ".join(missing_classes),
                "add deterministic fixtures for every required class",
            )
        )
    providers = {
        record.get("provider")
        for record in records
        if isinstance(record, dict) and "provider" in record.get("classes", [])
    }
    if not REQUIRED_PROVIDERS <= providers:
        problems.append(
            issue(
                CRITERIA[0],
                "missing_provider_fixture",
                MANIFEST_PATH,
                ", ".join(sorted(REQUIRED_PROVIDERS - providers)),
                "add harmless synthetic provider-shaped fixtures",
            )
        )

    listed_paths: set[str] = set()
    actual_content: dict[str, bytes] = {}
    total_bytes = 0
    giant_formats: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            problems.append(
                issue(CRITERIA[0], "invalid_fixture_record", MANIFEST_PATH, "Fixture record must be an object", "make generate-corpus")
            )
            continue
        fixture_id = str(record.get("id", "<unknown>"))
        relative = record.get("path")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or Path(relative).parent != Path(FIXTURE_ROOT)
        ):
            problems.append(
                issue(CRITERIA[0], "invalid_fixture_path", MANIFEST_PATH, fixture_id, "use a direct path under fixtures/research-corpus")
            )
            continue
        listed_paths.add(relative)
        required_objects = ("provenance", "redistribution_license", "expectations", "privacy_review", "safety_review")
        if (
            semver(record.get("version")) is None
            or any(not isinstance(record.get(field), dict) or not record[field] for field in required_objects)
            or not record.get("classes")
        ):
            problems.append(
                issue(
                    CRITERIA[0],
                    "incomplete_fixture_metadata",
                    MANIFEST_PATH,
                    fixture_id,
                    "complete version, provenance, license, expectations, privacy review, safety review, and classes",
                )
            )
        provenance = record.get("provenance", {})
        privacy = record.get("privacy_review", {})
        safety = record.get("safety_review", {})
        if (
            provenance.get("kind") != "project-created-synthetic"
            or provenance.get("customer_or_production_data") is not False
            or privacy.get("result") != "safe-synthetic"
            or any(privacy.get(field) is not False for field in ("personal_data", "live_credentials", "customer_data"))
            or safety.get("result") != "harmless-abstract-content"
            or safety.get("actionable_harm") is not False
        ):
            problems.append(
                issue(
                    CRITERIA[0],
                    "unsafe_fixture_provenance",
                    MANIFEST_PATH,
                    fixture_id,
                    "record completed synthetic, privacy, credential, customer-data, and harmless-content review",
                )
            )
        license_record = record.get("redistribution_license", {})
        if license_record.get("spdx") not in ALLOWED_LICENSES:
            problems.append(
                issue(
                    CRITERIA[0],
                    "unapproved_fixture_license",
                    MANIFEST_PATH,
                    f"{fixture_id}: {license_record.get('spdx')}",
                    "use a reviewed redistributable license and update the licensing inventory",
                )
            )
        path = root / relative
        if path.is_symlink():
            problems.append(
                issue(CRITERIA[0], "symlink_fixture", relative, fixture_id, "replace the symlink with a regular fixture")
            )
            continue
        try:
            content = path.read_bytes()
        except OSError as error:
            problems.append(
                issue(CRITERIA[0], "missing_fixture", relative, str(error), "make generate-corpus")
            )
            continue
        total_bytes += len(content)
        actual_content[relative] = content
        if len(content) > MAX_FIXTURE_BYTES:
            problems.append(
                issue(CRITERIA[0], "fixture_too_large", relative, str(len(content)), "keep each research fixture at or below 4 MiB")
            )
        if record.get("byte_count") != len(content) or record.get("sha256") != hashlib.sha256(content).hexdigest():
            problems.append(
                issue(CRITERIA[1], "fixture_digest_mismatch", relative, fixture_id, "make generate-corpus")
            )
        if "giant" in record.get("classes", []):
            giant_formats.add(str(record.get("format")))
            if len(content) < 1_000_000:
                problems.append(
                    issue(CRITERIA[0], "giant_fixture_too_small", relative, str(len(content)), "regenerate a fixture of at least 1,000,000 bytes")
                )
        for pattern in SECRET_PATTERNS.values():
            if pattern.search(content):
                problems.append(
                    issue(
                        CRITERIA[0],
                        "possible_secret_in_fixture",
                        relative,
                        "Sensitive pattern detected; fixture bytes and category withheld",
                        "replace the content with an unmistakably synthetic non-secret value",
                    )
                )
        for label, pattern in PII_PATTERNS.items():
            if pattern.search(content):
                problems.append(
                    issue(CRITERIA[0], "possible_pii_in_fixture", relative, label, "remove personal-looking data from the synthetic fixture")
                )
    if giant_formats != {"json", "jsonl"}:
        problems.append(
            issue(CRITERIA[0], "missing_giant_format", MANIFEST_PATH, str(sorted(giant_formats)), "include giant JSON and giant JSONL fixtures")
        )
    if total_bytes > MAX_TOTAL_BYTES:
        problems.append(
            issue(CRITERIA[0], "corpus_too_large", FIXTURE_ROOT, str(total_bytes), "keep the committed corpus at or below 16 MiB")
        )
    fixture_dir = root / FIXTURE_ROOT
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in fixture_dir.iterdir()
        if path.is_file() or path.is_symlink()
    } if fixture_dir.is_dir() else set()
    if actual_paths != listed_paths:
        problems.append(
            issue(
                CRITERIA[0],
                "fixture_inventory_mismatch",
                FIXTURE_ROOT,
                f"unlisted={sorted(actual_paths - listed_paths)}, missing={sorted(listed_paths - actual_paths)}",
                "make generate-corpus and reconcile the fixture manifest",
            )
        )

    generated = GENERATOR.expected_files()
    for relative, expected in generated.items():
        actual = actual_content.get(relative)
        if actual is None:
            try:
                actual = (root / relative).read_bytes()
            except OSError:
                continue
        if actual != expected:
            problems.append(
                issue(
                    CRITERIA[1],
                    "fixture_generation_mismatch",
                    relative,
                    "Committed bytes do not match the pinned generator, version, and seed",
                    "make generate-corpus",
                )
            )
    validate_history(root, manifest, problems)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    problems = validate(root)
    manifest = load_manifest(root, [])
    fixtures = manifest.get("fixtures", []) if isinstance(manifest, dict) else []
    report = {
        "schema_version": "1.0.0",
        "validation_ids": CRITERIA,
        "status": "pass" if not problems else "fail",
        "fixture_count": len(fixtures) if isinstance(fixtures, list) else 0,
        "fixture_classes": sorted(
            {
                fixture_class
                for record in fixtures
                if isinstance(record, dict)
                for fixture_class in record.get("classes", [])
            }
        ),
        "byte_count": sum(
            int(record.get("byte_count", 0))
            for record in fixtures
            if isinstance(record, dict)
        ),
        "secret_privacy_license_findings": sum(
            problem["code"]
            in {
                "possible_secret_in_fixture",
                "possible_pii_in_fixture",
                "unapproved_fixture_license",
                "unsafe_fixture_provenance",
            }
            for problem in problems
        ),
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
