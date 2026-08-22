#!/usr/bin/env python3
"""Validate Testament naming clearance and the Milestone 1 research registry."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CRITERIA = ["VAL-READY-006", "VAL-READY-007"]
TRACE_CRITERION = "VAL-READY-008"
ABUSE_CRITERION = "VAL-READY-009"
THREAT_PRIVACY_CRITERION = "VAL-READY-010"
STATES = {"draft", "in-review", "accepted", "blocked", "superseded"}
SEARCH_CLASSES = {
    "trademark",
    "package",
    "repository",
    "domain",
    "standards-ecosystem",
    "confusing-similarity",
}
PUBLIC_FILES = {
    "docs/research/privacy/data-inventory.md",
    "docs/research/privacy/no-content-egress.md",
    "docs/research/privacy/retention-deletion.md",
    "docs/research/privacy/sovereignty-profiles.md",
    "docs/research/README.md",
    "docs/research/naming-clearance.md",
    "docs/research/security/key-custody.md",
    "docs/research/studies/abuse-misuse.md",
    "docs/research/studies/trace-landscape.md",
    "docs/research/threats/attack-trees.md",
    "docs/research/threats/linddun.md",
    "docs/research/threats/stride.md",
    "policy/abuse-misuse-research.json",
    "policy/naming-clearance.json",
    "policy/research-manifest.json",
    "policy/trace-landscape.json",
    "schemas/abuse-misuse-research.schema.json",
    "schemas/naming-clearance.schema.json",
    "schemas/research-manifest.schema.json",
    "schemas/threat-privacy-sovereignty.schema.json",
    "schemas/trace-landscape.schema.json",
    "policy/threat-privacy-sovereignty.json",
}
TRACE_ECOSYSTEMS = {
    "openai",
    "anthropic",
    "gemini",
    "bedrock",
    "openai-compatible",
    "mcp",
    "a2a",
    "langgraph",
    "crewai",
    "autogen",
    "semantic-kernel",
    "llamaindex",
    "otlp",
    "opentelemetry-genai",
    "openinference",
    "langfuse",
    "mlflow",
    "langsmith",
    "phoenix",
    "raw-gateway-logs",
}
ABUSE_DOMAINS = {
    "cyber",
    "cbrn",
    "fraud",
    "compromised-accounts",
    "model-extraction",
    "evasion",
    "prompt-injection",
    "insider-risk",
    "coordinated-actors",
}
STRIDE_CATEGORIES = {
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
}
LINDDUN_CATEGORIES = {
    "linkability",
    "identifiability",
    "non-repudiation",
    "detectability",
    "disclosure",
    "unawareness",
    "non-compliance",
}
SOVEREIGNTY_PROFILES = {
    "isolated-sovereign",
    "boundary-sovereign",
    "metadata-redacted-external",
    "cloud-assisted",
}
KEY_PURPOSES = {"data-wrapping", "search-token", "secret", "audit-integrity"}
KEY_PROVIDERS = {
    "aws-kms",
    "gcp-cloud-kms",
    "azure-key-vault",
    "development-only",
}
SIGNING_KEY_CLASSES = {
    "KEY-RECEIPT",
    "KEY-SOVEREIGNTY",
    "KEY-RECOVERY",
    "KEY-RELEASE",
    "KEY-TLS",
    "KEY-CAPABILITY",
    "KEY-IDENTITY",
    "KEY-AZURE-BINDING",
    "KEY-TLS-SERVER",
    "KEY-MTLS-CLIENT",
    "KEY-TRUST-ANCHOR",
}
ANALYZER_TRUST_TIERS = {
    "ANALYZER-TRUSTED-BUILTIN",
    "ANALYZER-ISOLATED-EXTENSION",
    "ANALYZER-EXTERNAL",
}
EGRESS_SCHEMAS = {"EGRESS-KMS-01", "EGRESS-IDP-01", "EGRESS-OBS-01"}
LIFECYCLE_CLASSES = {
    "source artifacts and chunks",
    "derived projections and provenance",
    "findings, summaries, entity graphs, cases, and annotations",
    "jobs, analyzer state, and caches",
    "exports and download capabilities",
    "blind indexes and search tokens",
    "credentials and key material",
    "audit, holds, tombstones, and recovery authority",
    "backups, replicas, and external providers",
}
THREAT_PRIVACY_DELIVERABLES = {
    "RES-STUDY-STRIDE-001",
    "RES-STUDY-LINDDUN-001",
    "RES-STUDY-ATTACK-TREES-001",
    "RES-STUDY-DATA-INVENTORY-001",
    "RES-STUDY-SOVEREIGNTY-001",
    "RES-STUDY-NO-CONTENT-EGRESS-001",
    "RES-STUDY-RETENTION-DELETION-001",
    "RES-STUDY-KEY-CUSTODY-001",
}
REQUIRED_DELIVERABLES = {
    "RES-STUDY-NAMING-001": "study",
    "RES-STUDY-TRACE-LANDSCAPE-001": "study",
    "RES-STUDY-ABUSE-MISUSE-001": "study",
    "RES-STUDY-STRIDE-001": "study",
    "RES-STUDY-LINDDUN-001": "study",
    "RES-STUDY-ATTACK-TREES-001": "study",
    "RES-STUDY-DATA-INVENTORY-001": "study",
    "RES-STUDY-SOVEREIGNTY-001": "study",
    "RES-STUDY-NO-CONTENT-EGRESS-001": "study",
    "RES-STUDY-RETENTION-DELETION-001": "study",
    "RES-STUDY-KEY-CUSTODY-001": "study",
    "RES-STUDY-ANALYZER-EVALUATION-001": "study",
    "RES-CORPUS-SYNTHETIC-TRACE-001": "corpus",
    "RES-PROTOTYPE-GIANT-STREAM-001": "prototype",
    "RES-PROTOTYPE-EXACT-BYTE-001": "prototype",
    "RES-PROTOTYPE-COMPRESSION-ENCRYPTION-001": "prototype",
    "RES-PROTOTYPE-POSTGRES-STORAGE-001": "prototype",
    "RES-PROTOTYPE-BLIND-INDEX-001": "prototype",
    "RES-PROTOTYPE-KEY-ROTATION-001": "prototype",
    "RES-PROTOTYPE-DECISION-DURABILITY-001": "prototype",
    "RES-PROTOTYPE-ANALYZER-ISOLATION-001": "prototype",
    "RES-PROTOTYPE-OFFLINE-REPLAY-001": "prototype",
    "RES-BENCHMARK-GIANT-STREAM-001": "benchmark",
    "RES-BENCHMARK-EXACT-BYTE-001": "benchmark",
    "RES-BENCHMARK-COMPRESSION-ENCRYPTION-001": "benchmark",
    "RES-BENCHMARK-POSTGRES-STORAGE-001": "benchmark",
    "RES-BENCHMARK-BLIND-INDEX-001": "benchmark",
    "RES-BENCHMARK-KEY-ROTATION-001": "benchmark",
    "RES-BENCHMARK-DECISION-DURABILITY-001": "benchmark",
    "RES-BENCHMARK-ANALYZER-ISOLATION-001": "benchmark",
    "RES-BENCHMARK-OFFLINE-REPLAY-001": "benchmark",
    "RES-RFC-RAW-CAPTURE-001": "rfc",
    "RES-RFC-EVIDENCE-GRAPH-001": "rfc",
    "RES-RFC-ARTIFACTS-001": "rfc",
    "RES-RFC-FINDINGS-001": "rfc",
    "RES-RFC-ANALYZER-RUNS-001": "rfc",
    "RES-RFC-ENFORCEMENT-HOOKS-001": "rfc",
    "RES-RFC-POLICY-DECISIONS-001": "rfc",
    "RES-RFC-SIGNED-RECEIPTS-001": "rfc",
    "RES-RFC-AUDIT-CHECKPOINTS-001": "rfc",
    "RES-RFC-EXTENSION-NAMESPACES-001": "rfc",
    "RES-RFC-VERSIONING-001": "rfc",
    "RES-RFC-CONFORMANCE-PROFILES-001": "rfc",
    "RES-REVIEW-SECURITY-PRIVACY-001": "review",
    "RES-REVIEW-INTEROPERABILITY-001": "review",
    "RES-REVIEW-DEPLOYMENT-PERFORMANCE-001": "review",
    "RES-DECISION-NAMING-001": "decision",
    "RES-DECISION-RESEARCH-EXIT-001": "decision",
    "RES-DECISION-FIXTURE-PROMOTION-001": "decision",
    "RES-DECISION-RESEARCH-SEAL-001": "decision",
}
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
SEMVER_PATTERN = re.compile(r"\d+\.\d+\.\d+")
ID_PATTERN = re.compile(r"RES-(STUDY|CORPUS|PROTOTYPE|BENCHMARK|RFC|REVIEW|DECISION)-[A-Z0-9-]+-\d{3}")
SAFE_SCHEMA_PATTERNS = {
    r"^\d+\.\d+\.\d+$",
    r"^RES-(STUDY|CORPUS|PROTOTYPE|BENCHMARK|RFC|REVIEW|DECISION)-[A-Z0-9-]+-\d{3}$",
    r"^[0-9a-f]{40}$",
    r"^TB-[0-9]{2}$",
    r"^DATA-[0-9]{2}$",
    r"^(STRIDE|LINDDUN)-[0-9]{3}$",
    r"^TREE-[0-9]{2}$",
    r"^TREE-[0-9]{2}-L[0-9]{2}$",
    r"^CTRL-[A-Z0-9-]+$",
    r"^VAL-[A-Z0-9-]+$",
    r"^EGRESS-[A-Z0-9-]+$",
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


def load_object(root: Path, relative: str, problems: list[dict[str, str]], criterion: str) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(issue(criterion, "invalid_json", relative, str(error), "make verify-research"))
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(criterion, "invalid_json_shape", relative, "Root must be an object", "make verify-research")
        )
        return {}
    return value


def validate_schema_document(
    root: Path, relative: str, expected_id: str, problems: list[dict[str, str]]
) -> None:
    schema = load_object(root, relative, problems, CRITERIA[1])
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        problems.append(
            issue(CRITERIA[1], "invalid_schema_dialect", relative, "Schema must declare JSON Schema 2020-12", "repair schema")
        )
    if schema.get("$id") != expected_id or schema.get("type") != "object":
        problems.append(
            issue(CRITERIA[1], "invalid_schema_identity", relative, "Schema identity or root type drifted", "repair schema")
        )


def matches_type(instance: Any, expected: str) -> bool:
    return {
        "array": isinstance(instance, list),
        "boolean": isinstance(instance, bool),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "null": instance is None,
        "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
        "object": isinstance(instance, dict),
        "string": isinstance(instance, str),
    }.get(expected, False)


def schema_errors(instance: Any, schema: dict[str, Any], root_schema: dict[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    reference = schema.get("$ref")
    if isinstance(reference, str):
        if not reference.startswith("#/$defs/"):
            return [f"{path}: unsupported schema reference {reference}"]
        definition = root_schema.get("$defs", {}).get(reference.removeprefix("#/$defs/"))
        if not isinstance(definition, dict):
            return [f"{path}: unresolved schema reference {reference}"]
        return schema_errors(instance, definition, root_schema, path)
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: does not equal the required constant")
    choices = schema.get("enum")
    if isinstance(choices, list) and instance not in choices:
        errors.append(f"{path}: value is outside the controlled enumeration")
    expected = schema.get("type")
    expected_types = [expected] if isinstance(expected, str) else expected if isinstance(expected, list) else []
    if expected_types and not any(isinstance(value, str) and matches_type(instance, value) for value in expected_types):
        return [f"{path}: expected type {expected_types}"]
    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for field in required:
                if field not in instance:
                    errors.append(f"{path}: missing required property {field}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            if schema.get("additionalProperties") is False:
                for field in instance:
                    if field not in properties:
                        errors.append(f"{path}: undeclared property {field}")
            for field, value in instance.items():
                subschema = properties.get(field)
                if isinstance(subschema, dict):
                    errors.extend(schema_errors(value, subschema, root_schema, f"{path}.{field}"))
    if isinstance(instance, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: fewer than {minimum} items")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, value in enumerate(instance):
                errors.extend(schema_errors(value, items, root_schema, f"{path}[{index}]"))
    if isinstance(instance, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: shorter than {minimum} characters")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            if pattern not in SAFE_SCHEMA_PATTERNS:
                errors.append(f"{path}: schema pattern is outside the reviewed allowlist")
            elif len(instance) > 4096:
                errors.append(f"{path}: patterned string exceeds the 4096-character bound")
            else:
                try:
                    matches = re.fullmatch(pattern, instance)
                except re.error:
                    errors.append(f"{path}: schema pattern failed to compile")
                else:
                    if matches is None:
                        errors.append(f"{path}: does not match {pattern}")
        format_name = schema.get("format")
        if format_name == "date" and not valid_date(instance):
            errors.append(f"{path}: invalid ISO date")
        if format_name == "uri":
            parsed = urlparse(instance)
            if not parsed.scheme or not parsed.netloc:
                errors.append(f"{path}: invalid absolute URI")
    return errors


def validate_schema_instance(
    root: Path,
    schema_relative: str,
    instance_relative: str,
    criterion: str,
    problems: list[dict[str, str]],
) -> None:
    schema = load_object(root, schema_relative, problems, criterion)
    instance = load_object(root, instance_relative, problems, criterion)
    for message in schema_errors(instance, schema, schema):
        problems.append(
            issue(
                criterion,
                "schema_validation_failed",
                instance_relative,
                message,
                "repair the instance to match its JSON Schema 2020-12 contract",
            )
        )


def valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_naming(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/naming-clearance.json"
    record = load_object(root, relative, problems, CRITERIA[0])
    if record.get("schema_version") != "1.0.0" or record.get("feature_id") != "naming-clearance-and-research-registry":
        problems.append(
            issue(CRITERIA[0], "invalid_naming_record", relative, "Record identity or version drifted", "repair naming record")
        )
    searches = record.get("searches")
    if not isinstance(searches, list):
        searches = []
    classes = {
        item.get("class")
        for item in searches
        if isinstance(item, dict) and isinstance(item.get("class"), str)
    }
    missing = sorted(SEARCH_CLASSES - classes)
    if missing:
        problems.append(
            issue(
                CRITERIA[0],
                "missing_naming_search_class",
                relative,
                f"Missing search classes: {', '.join(missing)}",
                "complete every required naming search class",
            )
        )
    search_ids: list[str] = []
    unresolved = False
    for search in searches:
        if not isinstance(search, dict):
            problems.append(issue(CRITERIA[0], "invalid_naming_search", relative, "Search must be an object", "repair search"))
            continue
        search_ids.append(str(search.get("id", "")))
        required = (
            "id",
            "class",
            "query",
            "publisher",
            "title",
            "source_url",
            "accessed_at",
            "observation",
            "inference",
            "residual_risk",
        )
        if any(not search.get(field) for field in required) or not valid_date(search.get("accessed_at")):
            problems.append(
                issue(
                    CRITERIA[0],
                    "incomplete_naming_source",
                    relative,
                    f"{search.get('id')} lacks attributable, dated source or risk data",
                    "complete the search source record",
                )
            )
        source = search.get("source_url")
        if not isinstance(source, str) or urlparse(source).scheme != "https":
            problems.append(
                issue(CRITERIA[0], "invalid_naming_source_url", relative, str(source), "use a public HTTPS source")
            )
        if search.get("result") not in {"clear", "collision", "unresolved"}:
            problems.append(
                issue(CRITERIA[0], "invalid_naming_result", relative, str(search.get("result")), "use a controlled result")
            )
        unresolved = unresolved or search.get("result") == "unresolved"
    duplicates = [item for item, count in Counter(search_ids).items() if item and count > 1]
    if duplicates:
        problems.append(
            issue(CRITERIA[0], "duplicate_naming_search", relative, ", ".join(duplicates), "deduplicate search records")
        )
    review = record.get("review")
    if (
        not isinstance(review, dict)
        or not review.get("reviewer")
        or not review.get("role")
        or review.get("status") != "completed"
        or not valid_date(review.get("reviewed_at"))
        or not review.get("finding")
    ):
        problems.append(
            issue(CRITERIA[0], "incomplete_naming_review", relative, "Naming review is not attributable and dated", "complete review")
        )
    approval = record.get("approval")
    allowed_approval = {"conditionally-approved", "rejected", "pending"}
    if (
        not isinstance(approval, dict)
        or approval.get("status") not in allowed_approval
        or not approval.get("authority")
        or not approval.get("basis")
        or not approval.get("scope")
        or not approval.get("conditions")
        or not valid_date(approval.get("decided_at"))
    ):
        problems.append(
            issue(CRITERIA[0], "incomplete_naming_approval", relative, "Approval lacks authority, basis, date, scope, or conditions", "complete approval")
        )
    if unresolved and isinstance(approval, dict) and approval.get("status") == "approved":
        problems.append(
            issue(
                CRITERIA[0],
                "unsupported_naming_approval",
                relative,
                "Unresolved searches forbid unconditional approval",
                "record conditional approval, rejection, or pending status",
            )
        )
    if not record.get("legal_limitation") or not record.get("next_review"):
        problems.append(
            issue(CRITERIA[0], "missing_naming_limitation", relative, "Legal limitation or review trigger is missing", "complete risk limits")
        )


def validate_exact_coverage(
    *,
    relative: str,
    entries: Any,
    expected: set[str],
    criterion: str,
    noun: str,
    problems: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        problems.append(
            issue(
                criterion,
                f"invalid_{noun}_matrix",
                relative,
                f"{noun}s must be an array",
                f"repair {relative}",
            )
        )
        return []
    records = [entry for entry in entries if isinstance(entry, dict)]
    ids = [
        value
        for entry in records
        if isinstance(value := entry.get("id"), str)
    ]
    duplicates = sorted(
        str(value)
        for value, count in Counter(ids).items()
        if isinstance(value, str) and count > 1
    )
    if duplicates:
        problems.append(
            issue(
                criterion,
                f"duplicate_{noun}",
                relative,
                ", ".join(duplicates),
                f"deduplicate {noun} records",
            )
        )
    missing = sorted(expected - set(ids))
    extra = sorted(set(ids) - expected)
    if missing:
        problems.append(
            issue(
                criterion,
                f"missing_{noun}_coverage",
                relative,
                ", ".join(missing),
                f"add every required {noun}",
            )
        )
    if extra:
        problems.append(
            issue(
                criterion,
                f"unknown_{noun}",
                relative,
                ", ".join(extra),
                f"remove or register additional {noun}s",
            )
        )
    return records


def validate_research_sources(
    *,
    relative: str,
    records: list[dict[str, Any]],
    criterion: str,
    problems: list[dict[str, str]],
) -> None:
    source_ids: list[str] = []
    for record in records:
        record_id = str(record.get("id", "<unknown>"))
        sources = record.get("sources")
        if not isinstance(sources, list):
            continue
        for source in sources:
            if not isinstance(source, dict):
                continue
            source_id = source.get("id")
            if isinstance(source_id, str):
                source_ids.append(source_id)
            source_url = source.get("source_url")
            if not isinstance(source_url, str) or urlparse(source_url).scheme != "https":
                problems.append(
                    issue(
                        criterion,
                        "invalid_research_source_url",
                        relative,
                        f"{record_id}: {source_url}",
                        "use a public HTTPS primary source",
                    )
                )
            if not valid_date(source.get("accessed_at")):
                problems.append(
                    issue(
                        criterion,
                        "invalid_research_source_date",
                        relative,
                        f"{record_id}: {source.get('accessed_at')}",
                        "record a valid ISO access date",
                    )
                )
    duplicates = sorted(
        value for value, count in Counter(source_ids).items() if count > 1
    )
    if duplicates:
        problems.append(
            issue(
                criterion,
                "duplicate_research_source_id",
                relative,
                ", ".join(duplicates),
                "assign unique source IDs",
            )
        )


def validate_trace_landscape(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/trace-landscape.json"
    landscape = load_object(root, relative, problems, TRACE_CRITERION)
    if (
        landscape.get("schema_version") != "1.0.0"
        or landscape.get("deliverable_id") != "RES-STUDY-TRACE-LANDSCAPE-001"
        or landscape.get("validation_id") != TRACE_CRITERION
        or landscape.get("status") != "informative-draft"
    ):
        problems.append(
            issue(
                TRACE_CRITERION,
                "invalid_trace_landscape",
                relative,
                "Landscape identity, version, or informative status drifted",
                "repair the trace landscape identity",
            )
        )
    records = validate_exact_coverage(
        relative=relative,
        entries=landscape.get("ecosystems"),
        expected=TRACE_ECOSYSTEMS,
        criterion=TRACE_CRITERION,
        noun="trace_ecosystem",
        problems=problems,
    )
    for record in records:
        ecosystem_id = str(record.get("id", "<unknown>"))
        dimensions = ("transport", "projection", "unknown_fields", "lossiness")
        if any(not isinstance(record.get(dimension), dict) for dimension in dimensions):
            problems.append(
                issue(
                    TRACE_CRITERION,
                    "incomplete_trace_dimensions",
                    relative,
                    ecosystem_id,
                    "record transport, projection, unknown-field, and lossiness findings",
                )
            )
        if not record.get("samples") or not record.get("conclusions") or not record.get("open_questions"):
            problems.append(
                issue(
                    TRACE_CRITERION,
                    "incomplete_trace_research",
                    relative,
                    ecosystem_id,
                    "add samples, conclusions, and open questions",
                )
            )
        sources = record.get("sources")
        if not isinstance(sources, list) or not sources:
            problems.append(
                issue(
                    TRACE_CRITERION,
                    "unsourced_trace_ecosystem",
                    relative,
                    ecosystem_id,
                    "add dated primary sources",
                )
            )
    validate_research_sources(
        relative=relative,
        records=records,
        criterion=TRACE_CRITERION,
        problems=problems,
    )


def validate_abuse_research(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/abuse-misuse-research.json"
    research = load_object(root, relative, problems, ABUSE_CRITERION)
    if (
        research.get("schema_version") != "1.0.0"
        or research.get("deliverable_id") != "RES-STUDY-ABUSE-MISUSE-001"
        or research.get("validation_id") != ABUSE_CRITERION
        or research.get("status") != "informative-draft"
    ):
        problems.append(
            issue(
                ABUSE_CRITERION,
                "invalid_abuse_research",
                relative,
                "Research identity, version, or informative status drifted",
                "repair the abuse and misuse research identity",
            )
        )
    records = validate_exact_coverage(
        relative=relative,
        entries=research.get("risks"),
        expected=ABUSE_DOMAINS,
        criterion=ABUSE_CRITERION,
        noun="abuse_domain",
        problems=problems,
    )
    for record in records:
        risk_id = str(record.get("id", "<unknown>"))
        signals = record.get("signals")
        if not isinstance(signals, dict) or any(
            not isinstance(signals.get(timing), list) or not signals[timing]
            for timing in ("online", "nearline", "offline")
        ):
            problems.append(
                issue(
                    ABUSE_CRITERION,
                    "incomplete_timing_coverage",
                    relative,
                    risk_id,
                    "record online, nearline, and offline signals",
                )
            )
        required = (
            "authorized_use_twins",
            "false_positive_factors",
            "reviewer_path",
            "limitations",
            "unresolved_questions",
            "sources",
        )
        if any(not record.get(field) for field in required):
            problems.append(
                issue(
                    ABUSE_CRITERION,
                    "incomplete_harm_research",
                    relative,
                    risk_id,
                    "add counterexamples, false positives, review, limits, questions, and sources",
                )
            )
    validate_research_sources(
        relative=relative,
        records=records,
        criterion=ABUSE_CRITERION,
        problems=problems,
    )
    controls = research.get("cross_cutting_controls")
    if not isinstance(controls, dict) or any(
        not controls.get(field) for field in ("human_review", "appeals", "false_positives")
    ):
        problems.append(
            issue(
                ABUSE_CRITERION,
                "missing_cross_cutting_safeguards",
                relative,
                "Human review, appeals, and false-positive safeguards are required",
                "complete cross_cutting_controls",
            )
        )


def validate_threat_privacy_research(root: Path, problems: list[dict[str, str]]) -> None:
    relative = "policy/threat-privacy-sovereignty.json"
    research = load_object(root, relative, problems, THREAT_PRIVACY_CRITERION)
    if (
        research.get("schema_version") != "1.0.0"
        or research.get("feature_id") != "threat-privacy-sovereignty-research"
        or research.get("validation_id") != THREAT_PRIVACY_CRITERION
        or research.get("status") != "informative-draft"
    ):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "invalid_threat_privacy_research",
                relative,
                "Research identity, version, or informative status drifted",
                "repair the threat, privacy, and sovereignty research identity",
            )
        )
    deliverables = research.get("deliverable_ids")
    if (
        not isinstance(deliverables, list)
        or len(deliverables) != len(set(deliverables))
        or set(deliverables) != THREAT_PRIVACY_DELIVERABLES
    ):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_threat_privacy_deliverables",
                relative,
                "All eight registered studies must be represented exactly once",
                "restore exact VAL-READY-010 deliverable coverage",
            )
        )
    threats = research.get("threats")
    if not isinstance(threats, list):
        threats = []
    stride = {
        item.get("category")
        for item in threats
        if isinstance(item, dict) and item.get("framework") == "STRIDE"
    }
    linddun = {
        item.get("category")
        for item in threats
        if isinstance(item, dict) and item.get("framework") == "LINDDUN"
    }
    if stride != STRIDE_CATEGORIES:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_stride_coverage",
                relative,
                f"Expected {sorted(STRIDE_CATEGORIES)}, got {sorted(stride)}",
                "add exactly the required STRIDE categories",
            )
        )
    if linddun != LINDDUN_CATEGORIES:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_linddun_coverage",
                relative,
                f"Expected {sorted(LINDDUN_CATEGORIES)}, got {sorted(linddun)}",
                "add exactly the required LINDDUN categories",
            )
        )
    threat_ids: list[str] = []
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        threat_id = threat.get("id")
        if isinstance(threat_id, str):
            threat_ids.append(threat_id)
        required = (
            "assets",
            "actors",
            "boundary_ids",
            "preconditions",
            "mitigations",
            "validations",
            "owner",
            "residual_risk",
            "disposition",
        )
        if any(not threat.get(field) for field in required):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "incomplete_threat_mapping",
                    relative,
                    str(threat_id),
                    "map assets, actors, boundaries, preconditions, mitigations, validation, owner, residual risk, and disposition",
                )
            )
    duplicates = sorted(
        value for value, count in Counter(threat_ids).items() if count > 1
    )
    if duplicates:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "duplicate_threat_id",
                relative,
                ", ".join(duplicates),
                "assign unique stable threat IDs",
            )
        )
    boundary_ids = {
        item.get("id")
        for item in research.get("trust_boundaries", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    data_ids = {
        item.get("id")
        for item in research.get("data_inventory", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(boundary_ids) != len(research.get("trust_boundaries", [])):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "duplicate_or_invalid_boundary_id",
                relative,
                "Trust boundary IDs must be unique strings",
                "repair trust boundary IDs",
            )
        )
    if len(data_ids) != len(research.get("data_inventory", [])):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "duplicate_or_invalid_data_id",
                relative,
                "Data-class IDs must be unique strings",
                "repair data inventory IDs",
            )
        )
    known_threat_ids = set(threat_ids)
    control_records = research.get("controls")
    control_items = control_records if isinstance(control_records, list) else []
    control_ids = {
        item.get("id")
        for item in control_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    validation_records = research.get("validation_catalog")
    validation_items = (
        validation_records if isinstance(validation_records, list) else []
    )
    validation_ids = {
        item.get("id")
        for item in validation_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if (
        not isinstance(control_records, list)
        or len(control_ids) != len(control_records)
        or not isinstance(validation_records, list)
        or len(validation_ids) != len(validation_records)
    ):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "duplicate_or_invalid_control_mapping_id",
                relative,
                "Control and validation IDs must be unique strings",
                "repair control and validation catalogs",
            )
        )
    controls_by_id = {
        item["id"]: item
        for item in control_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for control_id, control in controls_by_id.items():
        linked = control.get("validation_ids")
        if (
            not isinstance(linked, list)
            or not linked
            or not set(linked) <= validation_ids
        ):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "incomplete_control_validation_binding",
                    relative,
                    control_id,
                    "link every control to one or more registered validations",
                )
            )
    for threat in threats:
        if not isinstance(threat, dict):
            continue
        unknown_boundaries = sorted(
            set(threat.get("boundary_ids", [])) - boundary_ids
            if isinstance(threat.get("boundary_ids"), list)
            else set()
        )
        if unknown_boundaries:
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "dangling_threat_boundary",
                    relative,
                    f"{threat.get('id')}: {', '.join(unknown_boundaries)}",
                    "link threats only to registered trust boundaries",
                )
            )
        unknown_data = sorted(
            set(threat.get("asset_data_ids", [])) - data_ids
            if isinstance(threat.get("asset_data_ids"), list)
            else set()
        )
        unknown_controls = sorted(
            set(threat.get("control_ids", [])) - control_ids
            if isinstance(threat.get("control_ids"), list)
            else set()
        )
        unknown_validations = sorted(
            set(threat.get("validation_ids", [])) - validation_ids
            if isinstance(threat.get("validation_ids"), list)
            else set()
        )
        if unknown_data or unknown_controls or unknown_validations:
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "dangling_threat_mapping",
                    relative,
                    f"{threat.get('id')}: data={unknown_data}, controls={unknown_controls}, validations={unknown_validations}",
                    "link threats only to registered data, control, and validation IDs",
                )
            )
        required_validations = {
            validation_id
            for control_id in threat.get("control_ids", [])
            if control_id in controls_by_id
            for validation_id in controls_by_id[control_id].get("validation_ids", [])
        }
        if not required_validations <= set(threat.get("validation_ids", [])):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "incomplete_threat_control_validation_edge",
                    relative,
                    str(threat.get("id")),
                    "Threat validation IDs must cover every linked control",
                )
            )
    trees = research.get("attack_trees")
    tree_ids: list[str] = []
    for tree in trees if isinstance(trees, list) else []:
        if not isinstance(tree, dict):
            continue
        if isinstance(tree.get("id"), str):
            tree_ids.append(tree["id"])
        unknown_threats = sorted(
            set(tree.get("threat_ids", [])) - known_threat_ids
            if isinstance(tree.get("threat_ids"), list)
            else set()
        )
        if unknown_threats:
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "dangling_attack_tree_threat",
                    relative,
                    f"{tree.get('id')}: {', '.join(unknown_threats)}",
                    "link attack trees only to registered stable threats",
                )
            )
        for branch in tree.get("branches", []) if isinstance(tree.get("branches"), list) else []:
            if not isinstance(branch, dict):
                continue
            unknown_leaf_threats = sorted(
                set(branch.get("threat_ids", [])) - known_threat_ids
            )
            unknown_leaf_controls = sorted(
                set(branch.get("control_ids", [])) - control_ids
            )
            unknown_leaf_validations = sorted(
                set(branch.get("validation_ids", [])) - validation_ids
            )
            if unknown_leaf_threats or unknown_leaf_controls or unknown_leaf_validations:
                problems.append(
                    issue(
                        THREAT_PRIVACY_CRITERION,
                        "dangling_attack_leaf_mapping",
                        relative,
                        f"{branch.get('id')}: threats={unknown_leaf_threats}, controls={unknown_leaf_controls}, validations={unknown_leaf_validations}",
                        "repair stable attack-tree leaf references",
                    )
                )
    if len(tree_ids) != len(set(tree_ids)):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "duplicate_attack_tree_id",
                relative,
                ", ".join(tree_ids),
                "assign unique stable attack-tree IDs",
            )
        )
    coverage = research.get("boundary_category_coverage")
    coverage_items = coverage if isinstance(coverage, list) else []
    coverage_ids = [
        item.get("boundary_id")
        for item in coverage_items
        if isinstance(item, dict)
    ]
    if (
        not isinstance(coverage, list)
        or len(coverage_ids) != len(set(coverage_ids))
        or set(coverage_ids) != boundary_ids
    ):
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_boundary_category_coverage",
                relative,
                "Every trust boundary must have exactly one STRIDE and LINDDUN coverage row",
                "restore complete boundary-category analysis",
            )
        )
    for row in coverage_items:
        if not isinstance(row, dict):
            continue
        for framework, categories in (
            ("stride", STRIDE_CATEGORIES),
            ("linddun", LINDDUN_CATEGORIES),
        ):
            cells = row.get(framework)
            if not isinstance(cells, dict) or set(cells) != categories:
                problems.append(
                    issue(
                        THREAT_PRIVACY_CRITERION,
                        "incomplete_boundary_category_coverage",
                        relative,
                        f"{row.get('boundary_id')}: {framework}",
                        "record every framework category",
                    )
                )
                continue
            for category, cell in cells.items():
                if not isinstance(cell, dict):
                    continue
                linked = cell.get("threat_ids")
                rationale = cell.get("not_applicable_rationale")
                unknown = (
                    set(linked) - known_threat_ids
                    if isinstance(linked, list)
                    else {"invalid"}
                )
                if unknown or (not linked and not rationale) or (linked and rationale):
                    problems.append(
                        issue(
                            THREAT_PRIVACY_CRITERION,
                            "invalid_boundary_category_disposition",
                            relative,
                            f"{row.get('boundary_id')} {framework} {category}",
                            "link stable threats or give one explicit not-applicable rationale",
                        )
                    )
    profiles = research.get("sovereignty_profiles")
    profile_ids = {
        item.get("id")
        for item in profiles if isinstance(item, dict)
    } if isinstance(profiles, list) else set()
    if profile_ids != SOVEREIGNTY_PROFILES:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_sovereignty_profiles",
                relative,
                f"Expected {sorted(SOVEREIGNTY_PROFILES)}, got {sorted(profile_ids)}",
                "add exactly the four approved sovereignty profiles",
            )
        )
    analyzer_tiers = research.get("analyzer_trust_tiers")
    analyzer_items = analyzer_tiers if isinstance(analyzer_tiers, list) else []
    analyzer_ids = {
        item.get("id")
        for item in analyzer_items
        if isinstance(item, dict)
    }
    if analyzer_ids != ANALYZER_TRUST_TIERS:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_analyzer_trust_tiers",
                relative,
                f"Expected {sorted(ANALYZER_TRUST_TIERS)}, got {sorted(analyzer_ids)}",
                "restore built-in, isolated-extension, and external analyzer tiers",
            )
        )
    for tier in analyzer_items:
        if not isinstance(tier, dict):
            continue
        if (
            not set(tier.get("control_ids", [])) <= control_ids
            or not set(tier.get("validation_ids", [])) <= validation_ids
        ):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "dangling_analyzer_trust_mapping",
                    relative,
                    str(tier.get("id")),
                    "link analyzer tiers to registered controls and validations",
                )
            )
    no_egress = research.get("no_content_egress_contract")
    protected = (
        no_egress.get("protected_data_classes")
        if isinstance(no_egress, dict)
        else []
    )
    if not isinstance(protected, list) or not protected or not set(protected) <= data_ids:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "invalid_no_egress_data_reference",
                relative,
                "No-content-egress protected classes must resolve to the data inventory",
                "repair protected data-class references",
            )
        )
    egress_schemas = (
        no_egress.get("permitted_egress_schemas", [])
        if isinstance(no_egress, dict)
        else []
    )
    egress_ids = {
        item.get("id")
        for item in egress_schemas
        if isinstance(item, dict)
    }
    if egress_ids != EGRESS_SCHEMAS:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_egress_schema_coverage",
                relative,
                f"Expected {sorted(EGRESS_SCHEMAS)}, got {sorted(egress_ids)}",
                "restore KMS, identity, and observability egress schemas",
            )
        )
    for egress in egress_schemas:
        if not isinstance(egress, dict):
            continue
        fields = egress.get("wire_fields")
        field_items = fields if isinstance(fields, list) else []
        names = [
            field.get("name")
            for field in field_items
            if isinstance(field, dict)
        ]
        if (
            not isinstance(fields, list)
            or not fields
            or len(names) != len(set(names))
            or not egress.get("authentication_headers")
            or not egress.get("provider_limits")
        ):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "incomplete_executable_egress_schema",
                    relative,
                    str(egress.get("id")),
                    "define unique typed wire fields, authentication headers, and provider limits",
                )
            )
    lifecycle = research.get("lifecycle_model")
    lifecycle_records = lifecycle.get("classes") if isinstance(lifecycle, dict) else []
    lifecycle_names = {
        item.get("name")
        for item in lifecycle_records
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if lifecycle_names != LIFECYCLE_CLASSES:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_lifecycle_coverage",
                relative,
                f"Expected {sorted(LIFECYCLE_CLASSES)}, got {sorted(lifecycle_names)}",
                "restore exact lifecycle class coverage",
            )
        )
    custody = research.get("key_custody")
    purpose_records = custody.get("purposes", []) if isinstance(custody, dict) else []
    provider_records = custody.get("providers", []) if isinstance(custody, dict) else []
    purpose_ids = {
        item.get("id")
        for item in purpose_records
        if isinstance(item, dict)
    }
    provider_ids = {
        item.get("id")
        for item in provider_records
        if isinstance(item, dict)
    }
    if purpose_ids != KEY_PURPOSES or provider_ids != KEY_PROVIDERS:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_key_custody_coverage",
                relative,
                "All four key purposes and provider classes are required",
                "restore key-purpose and provider coverage",
            )
        )
    signing_ids = {
        item.get("id")
        for item in (
            custody.get("signing_and_transport_keys", [])
            if isinstance(custody, dict)
            else []
        )
        if isinstance(item, dict)
    }
    if signing_ids != SIGNING_KEY_CLASSES:
        problems.append(
            issue(
                THREAT_PRIVACY_CRITERION,
                "incomplete_signing_key_coverage",
                relative,
                f"Expected {sorted(SIGNING_KEY_CLASSES)}, got {sorted(signing_ids)}",
                "restore receipt, attestation, recovery, release, TLS, capability, identity, and binding key classes",
            )
        )
    for section in (
        "trust_boundaries",
        "data_inventory",
        "attack_trees",
        "no_content_egress_contract",
        "lifecycle_model",
        "key_custody",
        "sources",
        "global_limitations",
    ):
        if not research.get(section):
            problems.append(
                issue(
                    THREAT_PRIVACY_CRITERION,
                    "missing_threat_privacy_section",
                    relative,
                    section,
                    f"complete {section}",
                )
            )
    validate_research_sources(
        relative=relative,
        records=[research],
        criterion=THREAT_PRIVACY_CRITERION,
        problems=problems,
    )


def repository_locator_path(locator: str) -> str:
    return locator.split("#", 1)[0]


def validate_manifest(root: Path, problems: list[dict[str, str]]) -> dict[str, Any]:
    relative = "policy/research-manifest.json"
    manifest = load_object(root, relative, problems, CRITERIA[1])
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("feature_id") != "naming-clearance-and-research-registry"
        or manifest.get("validation_ids") != CRITERIA
        or manifest.get("states") != ["draft", "in-review", "accepted", "blocked", "superseded"]
    ):
        problems.append(
            issue(CRITERIA[1], "invalid_research_manifest", relative, "Manifest identity, scope, or states drifted", "repair manifest")
        )
    records = manifest.get("deliverables")
    if not isinstance(records, list):
        records = []
        problems.append(issue(CRITERIA[1], "invalid_research_manifest", relative, "deliverables must be an array", "repair manifest"))
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    duplicate_ids = [value for value, count in Counter(ids).items() if value and count > 1]
    for duplicate in duplicate_ids:
        problems.append(
            issue(CRITERIA[1], "duplicate_deliverable_id", relative, str(duplicate), "deduplicate the manifest")
        )
    missing_ids = sorted(set(REQUIRED_DELIVERABLES) - set(ids))
    extra_ids = sorted(set(ids) - set(REQUIRED_DELIVERABLES))
    if missing_ids:
        problems.append(
            issue(CRITERIA[1], "missing_deliverable", relative, ", ".join(missing_ids), "restore required stable IDs")
        )
    if extra_ids:
        problems.append(
            issue(CRITERIA[1], "unknown_deliverable", relative, ", ".join(extra_ids), "register scope before adding IDs")
        )
    by_id = {
        record["id"]: record
        for record in records
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }
    artifact_owners: dict[str, list[str]] = {}
    resolved_repository_links = 0
    public_urls = 0
    for record in records:
        if not isinstance(record, dict):
            problems.append(issue(CRITERIA[1], "invalid_deliverable", relative, "Each deliverable must be an object", "repair entry"))
            continue
        record_id = record.get("id")
        if not isinstance(record_id, str) or not ID_PATTERN.fullmatch(record_id):
            problems.append(issue(CRITERIA[1], "invalid_deliverable_id", relative, str(record_id), "repair stable ID"))
            continue
        if record.get("type") != REQUIRED_DELIVERABLES.get(record_id):
            problems.append(
                issue(CRITERIA[1], "deliverable_type_drift", relative, record_id, "restore the registered deliverable type")
            )
        state = record.get("state")
        if state not in STATES:
            problems.append(
                issue(CRITERIA[1], "invalid_deliverable_state", relative, f"{record_id}: {state}", "use a controlled state")
            )
        required_text = ("title", "summary")
        if any(not record.get(field) for field in required_text):
            problems.append(issue(CRITERIA[1], "incomplete_deliverable", relative, record_id, "complete required fields"))
        if not SEMVER_PATTERN.fullmatch(str(record.get("version", ""))) or not SHA_PATTERN.fullmatch(
            str(record.get("commit", ""))
        ):
            problems.append(
                issue(CRITERIA[1], "invalid_deliverable_version", relative, record_id, "use SemVer and a full commit SHA")
            )
        owner = record.get("owner")
        if not isinstance(owner, dict) or not owner.get("role") or not owner.get("identity"):
            problems.append(issue(CRITERIA[1], "missing_deliverable_owner", relative, record_id, "assign an owner"))
        criteria = record.get("acceptance_criteria")
        if not isinstance(criteria, list) or not criteria or any(not isinstance(value, str) or not value for value in criteria):
            problems.append(
                issue(CRITERIA[1], "missing_acceptance_criteria", relative, record_id, "add acceptance criteria")
            )
        dependencies = record.get("dependencies")
        if not isinstance(dependencies, list) or any(
            not isinstance(value, str) or value not in REQUIRED_DELIVERABLES for value in dependencies
        ):
            problems.append(
                issue(CRITERIA[1], "invalid_deliverable_dependency", relative, record_id, "repair dependency IDs")
            )
        artifact = record.get("artifact")
        artifact_path = artifact.get("path") if isinstance(artifact, dict) else None
        if not isinstance(artifact_path, str) or artifact_path.startswith("/") or ".." in Path(artifact_path).parts:
            problems.append(issue(CRITERIA[1], "invalid_artifact_path", relative, record_id, "use a bounded public path"))
        else:
            artifact_owners.setdefault(artifact_path, []).append(record_id)
            artifact_exists = (root / artifact_path).is_file()
            artifact_is_symlink = (root / artifact_path).is_symlink()
            if state in {"in-review", "accepted", "superseded"} and not artifact_exists:
                problems.append(
                    issue(CRITERIA[1], "missing_research_artifact", artifact_path, record_id, "restore the reviewable artifact")
                )
            if state in {"in-review", "accepted", "superseded"} and artifact_is_symlink:
                problems.append(
                    issue(
                        CRITERIA[1],
                        "symlink_research_artifact",
                        artifact_path,
                        record_id,
                        "replace the symlink with a regular reviewable artifact",
                    )
                )
            if state in {"in-review", "accepted", "superseded"} and (root / ".git").exists():
                commit = record.get("commit")
                result = subprocess.run(
                    ["git", "show", f"{commit}:{artifact_path}"],
                    cwd=root,
                    capture_output=True,
                    check=False,
                )
                if result.returncode != 0:
                    problems.append(
                        issue(
                            CRITERIA[1],
                            "unbound_artifact_commit",
                            artifact_path,
                            f"{record_id} artifact is absent from commit {commit}",
                            "bind the reviewed artifact to an immutable commit",
                        )
                    )
                elif not artifact_is_symlink and (root / artifact_path).read_bytes() != result.stdout:
                    problems.append(
                        issue(
                            CRITERIA[1],
                            "unbound_artifact_content",
                            artifact_path,
                            f"{record_id} current bytes differ from bound commit {commit}",
                            "bind the exact reviewed artifact bytes to a new immutable commit",
                        )
                    )
        evidence = record.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            evidence = []
            problems.append(issue(CRITERIA[1], "missing_deliverable_evidence", relative, record_id, "add public evidence"))
        public_evidence = 0
        for item in evidence:
            if not isinstance(item, dict):
                continue
            if item.get("visibility") == "public":
                public_evidence += 1
            locator = item.get("locator")
            if not isinstance(locator, str) or not item.get("claim_supported"):
                problems.append(
                    issue(CRITERIA[1], "invalid_evidence_reference", relative, record_id, "complete evidence reference")
                )
                continue
            if item.get("kind") == "repository":
                path = repository_locator_path(locator)
                if path.startswith("/") or ".." in Path(path).parts or not (root / path).is_file():
                    problems.append(
                        issue(CRITERIA[1], "unresolved_evidence_link", locator, record_id, "restore the public repository evidence")
                    )
                else:
                    resolved_repository_links += 1
            elif item.get("kind") == "url":
                if urlparse(locator).scheme != "https":
                    problems.append(
                        issue(CRITERIA[1], "unresolved_evidence_link", locator, record_id, "use a public HTTPS source")
                    )
                else:
                    public_urls += 1
            else:
                problems.append(
                    issue(CRITERIA[1], "invalid_evidence_kind", relative, record_id, "use repository or url evidence")
                )
        if public_evidence == 0:
            problems.append(
                issue(CRITERIA[1], "private_only_evidence", relative, record_id, "add at least one public evidence reference")
            )
        review = record.get("review")
        if not isinstance(review, dict) or not review.get("reviewer") or review.get("status") not in {"pending", "completed"}:
            problems.append(issue(CRITERIA[1], "invalid_review", relative, record_id, "complete review metadata"))
        decision = record.get("decision")
        if not isinstance(decision, dict) or decision.get("status") not in {"pending", "approved", "rejected"}:
            problems.append(issue(CRITERIA[1], "invalid_decision", relative, record_id, "complete decision metadata"))
        if state == "accepted":
            if not isinstance(review, dict) or review.get("status") != "completed" or not valid_date(review.get("reviewed_at")):
                problems.append(
                    issue(CRITERIA[1], "accepted_without_review", relative, record_id, "complete attributable review")
                )
            if (
                not isinstance(decision, dict)
                or decision.get("status") != "approved"
                or not valid_date(decision.get("decided_at"))
                or not decision.get("authority")
            ):
                problems.append(
                    issue(CRITERIA[1], "accepted_without_decision", relative, record_id, "record accountable approval")
                )
        lineage = record.get("lineage")
        if not isinstance(lineage, dict):
            lineage = {}
        predecessor = lineage.get("supersedes")
        successor = lineage.get("superseded_by")
        if state == "superseded" and not successor:
            problems.append(
                issue(CRITERIA[1], "missing_supersession_lineage", relative, record_id, "link the accepted successor")
            )
        if predecessor:
            prior = by_id.get(predecessor)
            if not prior or prior.get("lineage", {}).get("superseded_by") != record_id:
                problems.append(
                    issue(CRITERIA[1], "broken_supersession_lineage", relative, record_id, "repair reciprocal lineage")
                )
        if successor:
            later = by_id.get(successor)
            if (
                not later
                or later.get("lineage", {}).get("supersedes") != record_id
                or later.get("state") != "accepted"
            ):
                problems.append(
                    issue(CRITERIA[1], "broken_supersession_lineage", relative, record_id, "repair reciprocal lineage")
                )
    for path, owners in artifact_owners.items():
        if len(owners) > 1:
            problems.append(
                issue(
                    CRITERIA[1],
                    "shared_research_artifact",
                    path,
                    f"Incompatible deliverables share one artifact: {', '.join(owners)}",
                    "assign one artifact path per stable deliverable",
                )
            )
    indexed = set(artifact_owners)
    research_root = root / "docs/research"
    if research_root.is_dir():
        for path in research_root.rglob("*.md"):
            relative_path = path.relative_to(root).as_posix()
            if relative_path == "docs/research/README.md":
                continue
            if relative_path not in indexed:
                problems.append(
                    issue(
                        CRITERIA[1],
                        "orphaned_research_artifact",
                        relative_path,
                        "Research artifact is absent from the registry",
                        "register or remove the orphaned artifact",
                    )
                )
    manifest["_validation_summary"] = {
        "required_deliverables": len(REQUIRED_DELIVERABLES),
        "registered_deliverables": len(records),
        "resolved_repository_links": resolved_repository_links,
        "public_urls": public_urls,
        "states": dict(sorted(Counter(record.get("state") for record in records if isinstance(record, dict)).items())),
        "lineage_edges": sum(
            1
            for record in records
            if isinstance(record, dict) and isinstance(record.get("lineage"), dict) and record["lineage"].get("supersedes")
        ),
    }
    return manifest


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    for relative in sorted(PUBLIC_FILES):
        if not (root / relative).is_file():
            problems.append(
                issue(CRITERIA[1], "missing_public_research_file", relative, "Required public file is absent", f"restore {relative}")
            )
    validate_schema_document(
        root,
        "schemas/naming-clearance.schema.json",
        "https://github.com/Factory-AI/testament/schemas/naming-clearance.schema.json",
        problems,
    )
    validate_schema_document(
        root,
        "schemas/research-manifest.schema.json",
        "https://github.com/Factory-AI/testament/schemas/research-manifest.schema.json",
        problems,
    )
    validate_schema_document(
        root,
        "schemas/trace-landscape.schema.json",
        "https://github.com/Factory-AI/testament/schemas/trace-landscape.schema.json",
        problems,
    )
    validate_schema_document(
        root,
        "schemas/abuse-misuse-research.schema.json",
        "https://github.com/Factory-AI/testament/schemas/abuse-misuse-research.schema.json",
        problems,
    )
    validate_schema_document(
        root,
        "schemas/threat-privacy-sovereignty.schema.json",
        "https://github.com/Factory-AI/testament/schemas/threat-privacy-sovereignty.schema.json",
        problems,
    )
    validate_schema_instance(
        root,
        "schemas/naming-clearance.schema.json",
        "policy/naming-clearance.json",
        CRITERIA[0],
        problems,
    )
    validate_schema_instance(
        root,
        "schemas/research-manifest.schema.json",
        "policy/research-manifest.json",
        CRITERIA[1],
        problems,
    )
    validate_schema_instance(
        root,
        "schemas/trace-landscape.schema.json",
        "policy/trace-landscape.json",
        TRACE_CRITERION,
        problems,
    )
    validate_schema_instance(
        root,
        "schemas/abuse-misuse-research.schema.json",
        "policy/abuse-misuse-research.json",
        ABUSE_CRITERION,
        problems,
    )
    validate_schema_instance(
        root,
        "schemas/threat-privacy-sovereignty.schema.json",
        "policy/threat-privacy-sovereignty.json",
        THREAT_PRIVACY_CRITERION,
        problems,
    )
    validate_naming(root, problems)
    validate_manifest(root, problems)
    validate_trace_landscape(root, problems)
    validate_abuse_research(root, problems)
    validate_threat_privacy_research(root, problems)
    return problems


def report(root: Path) -> dict[str, Any]:
    problems = validate(root)
    manifest = load_object(root, "policy/research-manifest.json", [], CRITERIA[1])
    naming = load_object(root, "policy/naming-clearance.json", [], CRITERIA[0])
    trace = load_object(root, "policy/trace-landscape.json", [], TRACE_CRITERION)
    abuse = load_object(root, "policy/abuse-misuse-research.json", [], ABUSE_CRITERION)
    threat_privacy = load_object(
        root,
        "policy/threat-privacy-sovereignty.json",
        [],
        THREAT_PRIVACY_CRITERION,
    )
    records = manifest.get("deliverables", []) if isinstance(manifest, dict) else []
    repository_links = 0
    public_urls = sum(
        1
        for search in naming.get("searches", [])
        if isinstance(search, dict)
        and isinstance(search.get("source_url"), str)
        and urlparse(search["source_url"]).scheme == "https"
    )
    lineage_edges = 0
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        for evidence in record.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            repository_links += evidence.get("kind") == "repository"
            public_urls += evidence.get("kind") == "url"
        lineage = record.get("lineage")
        lineage_edges += isinstance(lineage, dict) and bool(lineage.get("supersedes"))
    research_source_urls = sum(
        1
        for collection in (
            trace.get("ecosystems", []),
            abuse.get("risks", []),
            [threat_privacy],
        )
        if isinstance(collection, list)
        for record in collection
        if isinstance(record, dict)
        for source in record.get("sources", [])
        if isinstance(source, dict)
        and isinstance(source.get("source_url"), str)
        and urlparse(source["source_url"]).scheme == "https"
    )
    public_urls += research_source_urls
    return {
        "schema_version": "1.0.0",
        "criteria": CRITERIA
        + [TRACE_CRITERION, ABUSE_CRITERION, THREAT_PRIVACY_CRITERION],
        "status": "pass" if not problems else "fail",
        "schema_report": {
            "draft": "2020-12",
            "documents": sorted(path for path in PUBLIC_FILES if path.startswith("schemas/")),
            "instances": [
                "policy/abuse-misuse-research.json",
                "policy/naming-clearance.json",
                "policy/research-manifest.json",
                "policy/threat-privacy-sovereignty.json",
                "policy/trace-landscape.json",
            ],
        },
        "coverage_report": {
            "required": len(REQUIRED_DELIVERABLES),
            "registered": len(records) if isinstance(records, list) else 0,
            "missing": sorted(set(REQUIRED_DELIVERABLES) - {record.get("id") for record in records if isinstance(record, dict)}),
        },
        "resolved_link_report": {
            "repository_references": repository_links,
            "public_url_references": public_urls,
            "research_source_urls": research_source_urls,
            "network_resolution_performed": False,
            "unresolved": sum(1 for problem in problems if problem["code"] == "unresolved_evidence_link"),
        },
        "lifecycle_lineage_report": {
            "states": dict(sorted(Counter(record.get("state") for record in records if isinstance(record, dict)).items())),
            "lineage_edges": lineage_edges,
            "invalid": sum(1 for problem in problems if "lineage" in problem["code"] or "state" in problem["code"]),
        },
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    result = report(args.root.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
