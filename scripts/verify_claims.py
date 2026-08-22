#!/usr/bin/env python3
"""Validate claim evidence and normative/informative source boundaries."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import fnmatch
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CLAIMS_CRITERION = "VAL-READY-016"
BOUNDARIES_CRITERION = "VAL-READY-017"
PUBLIC_FILES = {
    "docs/rfcs/0003-raw-capture.md",
    "docs/rfcs/0004-evidence-graph.md",
    "docs/rfcs/0005-artifacts.md",
    "docs/rfcs/0006-findings.md",
    "docs/rfcs/0007-analyzer-runs.md",
    "docs/rfcs/0008-enforcement-hooks.md",
    "docs/rfcs/0009-policy-decisions.md",
    "docs/rfcs/0010-signed-receipts.md",
    "docs/rfcs/0011-audit-checkpoints.md",
    "docs/rfcs/0012-extension-namespaces.md",
    "docs/rfcs/0013-versioning.md",
    "docs/rfcs/0014-conformance-profiles.md",
    "docs/rfcs/index.json",
    "docs/research/benchmarks/reproduction.json",
    "docs/research/corpus/manifest.json",
    "docs/standards-status.md",
    "policy/architecture.json",
    "policy/claims-ledger.json",
    "policy/normative-sources.json",
    "policy/prototype-claims.json",
    "policy/threat-privacy-sovereignty.json",
    "schemas/claims-ledger.schema.json",
    "schemas/normative-sources.schema.json",
    "scripts/verify_research.py",
}
EXPECTED_ARCHITECTURE_POINTERS = {
    "/system/artifact",
    "/system/database",
    "/system/operational_surface",
    "/system/standards_surface",
    "/authoritative_data/source",
    "/authoritative_data/derived",
    "/invariants/0",
    "/invariants/1",
    "/invariants/2",
    "/invariants/3",
    "/invariants/4",
    "/invariants/5",
}
EXPECTED_RELEASE_POINTERS = {f"/claims/{index}" for index in range(9)}
MAX_RFC_BYTES = 512 * 1024
MAX_SOURCE_COUNT = 64
MAX_SECTION_COUNT = 32


def issue(
    criterion_id: str,
    code: str,
    path: str,
    message: str,
    remediation_command: str = "make verify-claims",
) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion_id,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": remediation_command,
    }


def load_object(
    root: Path,
    relative: str,
    criterion: str,
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(issue(criterion, "invalid_json", relative, str(error)))
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(criterion, "invalid_json_shape", relative, "Root must be an object")
        )
        return {}
    return value


def valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_schema(
    root: Path,
    schema_relative: str,
    instance_relative: str,
    expected_id: str,
    criterion: str,
    problems: list[dict[str, str]],
) -> None:
    schema = load_object(root, schema_relative, criterion, problems)
    instance = load_object(root, instance_relative, criterion, problems)
    if (
        schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id") != expected_id
        or schema.get("type") != "object"
    ):
        problems.append(
            issue(
                criterion,
                "invalid_schema_identity",
                schema_relative,
                "Schema must use JSON Schema 2020-12 and the registered identity",
            )
        )
    validator_path = root / "scripts/verify_research.py"
    spec = importlib.util.spec_from_file_location(
        "claims_schema_validator", validator_path
    )
    if not spec or not spec.loader:
        problems.append(
            issue(
                criterion,
                "invalid_schema_validator",
                validator_path.as_posix(),
                "Cannot load the shared research schema validator",
            )
        )
        return
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    for message in validator.schema_errors(instance, schema, schema):
        problems.append(
            issue(criterion, "schema_validation_failed", instance_relative, message)
        )


def pointer_value(document: Any, pointer: str) -> Any:
    current = document
    if not pointer.startswith("/"):
        raise KeyError(pointer)
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(pointer)
    return current


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def duplicate_values(values: list[Any]) -> list[str]:
    return sorted(
        str(value)
        for value, count in Counter(values).items()
        if value is not None and count > 1
    )


def validate_claims(root: Path, problems: list[dict[str, str]]) -> dict[str, Any]:
    relative = "policy/claims-ledger.json"
    ledger = load_object(root, relative, CLAIMS_CRITERION, problems)
    if (
        ledger.get("schema_version") != "1.0.0"
        or ledger.get("feature_id") != "claims-ledger-and-normative-boundaries"
        or ledger.get("validation_id") != CLAIMS_CRITERION
    ):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "invalid_claims_ledger",
                relative,
                "Claims ledger identity or criterion drifted",
            )
        )
    architecture = load_object(
        root, "policy/architecture.json", CLAIMS_CRITERION, problems
    )
    prototype_claims = load_object(
        root, "policy/prototype-claims.json", CLAIMS_CRITERION, problems
    )
    architecture_source = ledger.get("architecture_source")
    declared_pointers = (
        architecture_source.get("claim_pointers", [])
        if isinstance(architecture_source, dict)
        else []
    )
    if (
        not isinstance(declared_pointers, list)
        or set(declared_pointers) != EXPECTED_ARCHITECTURE_POINTERS
        or len(declared_pointers) != len(EXPECTED_ARCHITECTURE_POINTERS)
    ):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "incomplete_architecture_source_inventory",
                relative,
                "Architecture source inventory must enumerate each machine claim exactly once",
            )
        )

    evidence_items = ledger.get("evidence")
    evidence_records = (
        [item for item in evidence_items if isinstance(item, dict)]
        if isinstance(evidence_items, list)
        else []
    )
    evidence_ids = [item.get("id") for item in evidence_records]
    if duplicates := duplicate_values(evidence_ids):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "duplicate_claim_evidence",
                relative,
                ", ".join(duplicates),
            )
        )
    evidence_by_id = {
        item["id"]: item
        for item in evidence_records
        if isinstance(item.get("id"), str)
    }
    invalid_evidence_ids: set[str] = set()
    for evidence in evidence_records:
        evidence_id = str(evidence.get("id", "<unknown>"))
        required = ("publisher", "title", "version", "claim_supported", "environment")
        dated = valid_date(evidence.get("accessed_at")) and (
            valid_date(evidence.get("publication_date"))
            or isinstance(evidence.get("tested_commit"), str)
        )
        if any(not evidence.get(field) for field in required) or not dated:
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "incomplete_claim_evidence",
                    relative,
                    evidence_id,
                )
            )
        path_value = evidence.get("path")
        url_value = evidence.get("url")
        if bool(path_value) == bool(url_value):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "invalid_claim_evidence_locator",
                    relative,
                    f"{evidence_id} requires exactly one repository path or public URL",
                )
            )
        if isinstance(path_value, str):
            if (
                path_value.startswith("/")
                or ".." in Path(path_value).parts
                or not (root / path_value).is_file()
            ):
                invalid_evidence_ids.add(evidence_id)
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "inaccessible_claim_evidence",
                        path_value,
                        evidence_id,
                    )
                )
            elif evidence.get("sha256") != file_digest(root / path_value):
                invalid_evidence_ids.add(evidence_id)
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "claim_evidence_digest_drift",
                        path_value,
                        evidence_id,
                    )
                )
            if evidence.get("accessibility") != "public-repository":
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "invalid_claim_evidence_accessibility",
                        relative,
                        evidence_id,
                    )
                )
        if isinstance(url_value, str):
            if urlparse(url_value).scheme != "https":
                invalid_evidence_ids.add(evidence_id)
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "inaccessible_claim_evidence",
                        url_value,
                        evidence_id,
                    )
                )
            if evidence.get("accessibility") != "public-url":
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "invalid_claim_evidence_accessibility",
                        relative,
                        evidence_id,
                    )
                )

    claims_value = ledger.get("claims")
    claims = (
        [item for item in claims_value if isinstance(item, dict)]
        if isinstance(claims_value, list)
        else []
    )
    claim_ids = [claim.get("id") for claim in claims]
    if duplicates := duplicate_values(claim_ids):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "duplicate_claim_id",
                relative,
                ", ".join(duplicates),
            )
        )
    architecture_claims = [
        claim for claim in claims if claim.get("category") == "architecture-shaping"
    ]
    release_claims = [
        claim for claim in claims if claim.get("category") == "release-blocking"
    ]
    architecture_pointers = {
        claim.get("source_pointer")
        for claim in architecture_claims
        if claim.get("source_path") == "policy/architecture.json"
    }
    release_pointers = {
        claim.get("source_pointer")
        for claim in release_claims
        if claim.get("source_path") == "policy/prototype-claims.json"
    }
    missing_architecture = sorted(EXPECTED_ARCHITECTURE_POINTERS - architecture_pointers)
    extra_architecture = sorted(architecture_pointers - EXPECTED_ARCHITECTURE_POINTERS)
    if missing_architecture:
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "missing_architecture_claim",
                relative,
                ", ".join(missing_architecture),
            )
        )
    if extra_architecture or len(architecture_claims) != len(
        EXPECTED_ARCHITECTURE_POINTERS
    ):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "invalid_architecture_claim_coverage",
                relative,
                ", ".join(extra_architecture),
            )
        )
    if release_pointers != EXPECTED_RELEASE_POINTERS or len(release_claims) != len(
        EXPECTED_RELEASE_POINTERS
    ):
        problems.append(
            issue(
                CLAIMS_CRITERION,
                "incomplete_release_claim_coverage",
                relative,
                "Every prototype conclusion must have exactly one release-blocking claim trace",
            )
        )

    source_documents = {
        "policy/architecture.json": architecture,
        "policy/prototype-claims.json": prototype_claims,
    }
    known_claim_ids = {value for value in claim_ids if isinstance(value, str)}
    for claim in claims:
        claim_id = str(claim.get("id", "<unknown>"))
        required_reasoning = (
            "claim",
            "observation",
            "inference",
            "uncertainty",
            "owner",
        )
        if any(not claim.get(field) for field in required_reasoning) or not claim.get(
            "limitations"
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "incomplete_claim_reasoning",
                    relative,
                    claim_id,
                )
            )
        evidence_links = claim.get("evidence_ids")
        linked_evidence = (
            [evidence_by_id.get(value) for value in evidence_links]
            if isinstance(evidence_links, list)
            else []
        )
        if (
            not linked_evidence
            or any(item is None for item in linked_evidence)
            or len(evidence_links) != len(set(evidence_links))
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "dangling_claim_evidence",
                    relative,
                    claim_id,
                )
            )
        elif not any(
            isinstance(item, dict) and item.get("path") == claim.get("source_path")
            for item in linked_evidence
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "claim_missing_primary_source_evidence",
                    relative,
                    claim_id,
                )
            )
        contradictions = claim.get("contradictory_evidence")
        if not isinstance(contradictions, list) or not contradictions:
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "incomplete_claim_contradiction",
                    relative,
                    claim_id,
                )
            )
        else:
            for contradiction in contradictions:
                if not isinstance(contradiction, dict):
                    continue
                evidence_id = contradiction.get("evidence_id")
                if evidence_id is not None and evidence_id not in evidence_by_id:
                    problems.append(
                        issue(
                            CLAIMS_CRITERION,
                            "dangling_claim_contradiction",
                            relative,
                            claim_id,
                        )
                    )
        review = claim.get("review")
        if not isinstance(review, dict):
            review = {}
        review_status = review.get("status")
        if (
            not review.get("reviewer")
            or not review.get("role")
            or not review.get("independence")
            or review_status not in {"pending", "completed"}
            or (
                review_status == "completed"
                and not valid_date(review.get("reviewed_at"))
            )
            or (review_status == "pending" and review.get("reviewed_at") is not None)
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "incomplete_claim_review",
                    relative,
                    claim_id,
                )
            )
        supersession = claim.get("supersession")
        if (
            not isinstance(supersession, dict)
            or set(supersession)
            != {"supersedes", "superseded_by", "history"}
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "incomplete_claim_supersession",
                    relative,
                    claim_id,
                )
            )
        else:
            predecessor = supersession.get("supersedes")
            successor = supersession.get("superseded_by")
            if predecessor and predecessor not in known_claim_ids:
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "broken_claim_supersession",
                        relative,
                        claim_id,
                    )
                )
            if successor and successor not in known_claim_ids:
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "broken_claim_supersession",
                        relative,
                        claim_id,
                    )
                )
            if claim.get("status") == "superseded" and not successor:
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "broken_claim_supersession",
                        relative,
                        claim_id,
                    )
                )
        source_path = claim.get("source_path")
        source_pointer = claim.get("source_pointer")
        source_document = source_documents.get(source_path)
        try:
            source_value = pointer_value(source_document, source_pointer)
        except (KeyError, IndexError, TypeError, ValueError):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "unresolved_claim_source",
                    str(source_path),
                    f"{claim_id}: {source_pointer}",
                )
            )
        else:
            expected_claim = (
                source_value.get("claim")
                if isinstance(source_value, dict)
                else source_value
            )
            if not isinstance(expected_claim, str):
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "invalid_claim_source",
                        str(source_path),
                        claim_id,
                    )
                )
            elif claim.get("claim") != expected_claim:
                problems.append(
                    issue(
                        CLAIMS_CRITERION,
                        "claim_source_text_drift",
                        str(source_path),
                        claim_id,
                    )
                )
        if claim.get("status") == "supported" and (
            review_status != "completed"
            or any(value in invalid_evidence_ids for value in evidence_links)
        ):
            problems.append(
                issue(
                    CLAIMS_CRITERION,
                    "unsupported_claim_status",
                    relative,
                    claim_id,
                )
            )
    return ledger


def validate_boundaries(
    root: Path, problems: list[dict[str, str]]
) -> dict[str, Any]:
    relative = "policy/normative-sources.json"
    inventory = load_object(root, relative, BOUNDARIES_CRITERION, problems)
    if (
        inventory.get("schema_version") != "1.0.0"
        or inventory.get("feature_id") != "claims-ledger-and-normative-boundaries"
        or inventory.get("validation_id") != BOUNDARIES_CRITERION
    ):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "invalid_normative_inventory",
                relative,
                "Normative source inventory identity or criterion drifted",
            )
        )
    rfc_index = load_object(
        root, "docs/rfcs/index.json", BOUNDARIES_CRITERION, problems
    )
    protocol_records = {
        record["id"]: record
        for record in rfc_index.get("records", [])
        if isinstance(record, dict)
        and isinstance(record.get("protocol_area"), str)
        and isinstance(record.get("id"), str)
    }
    sources_value = inventory.get("sources")
    sources = (
        [item for item in sources_value if isinstance(item, dict)]
        if isinstance(sources_value, list)
        else []
    )
    if len(sources) > MAX_SOURCE_COUNT:
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "normative_source_inventory_too_large",
                relative,
                f"Source count exceeds {MAX_SOURCE_COUNT}",
            )
        )
    source_ids = [source.get("id") for source in sources]
    if duplicates := duplicate_values(source_ids):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "duplicate_normative_source",
                relative,
                ", ".join(duplicates),
            )
        )
    source_by_id = {
        source["id"]: source
        for source in sources
        if isinstance(source.get("id"), str)
    }
    rfc_source_ids = {source.get("rfc_id") for source in sources}
    if rfc_source_ids != set(protocol_records) or len(sources) != len(
        protocol_records
    ):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "incomplete_normative_source_inventory",
                relative,
                "Each indexed trust-plane protocol RFC must be inventoried exactly once",
            )
        )
    for source in sources:
        source_id = str(source.get("id", "<unknown>"))
        record = protocol_records.get(source.get("rfc_id"))
        if not isinstance(record, dict):
            continue
        if source.get("status") != record.get("status"):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "normative_source_status_drift",
                    relative,
                    source_id,
                )
            )
        if (
            source.get("path") != record.get("path")
            or source.get("version") != record.get("version")
            or record.get("normative") is not True
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "normative_source_metadata_drift",
                    relative,
                    source_id,
                )
            )
        path_value = source.get("path")
        if not isinstance(path_value, str) or not (root / path_value).is_file():
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "missing_normative_source",
                    str(path_value),
                    source_id,
                )
            )
            continue
        source_bytes = (root / path_value).read_bytes()
        actual_digest = hashlib.sha256(source_bytes).hexdigest()
        if source.get("sha256") != actual_digest or source.get(
            "sha256"
        ) != record.get("sha256"):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "normative_source_digest_drift",
                    path_value,
                    source_id,
                )
            )
        if len(source_bytes) > MAX_RFC_BYTES:
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "normative_source_too_large",
                    path_value,
                    source_id,
                )
            )
            continue
        try:
            text = source_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        normative_sections = source.get("normative_sections")
        informative_sections = source.get("informative_sections")
        if (
            isinstance(normative_sections, list)
            and len(normative_sections) > MAX_SECTION_COUNT
        ) or (
            isinstance(informative_sections, list)
            and len(informative_sections) > MAX_SECTION_COUNT
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "normative_section_inventory_too_large",
                    path_value,
                    source_id,
                )
            )
        section_names = {
            match.group(1)
            for match in re.finditer(
                r"^#{2,4}\s+(.+?)\s*$",
                text,
                flags=re.MULTILINE,
            )
        }
        if (
            not isinstance(normative_sections, list)
            or not normative_sections
            or any(section not in section_names for section in normative_sections)
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "missing_normative_section",
                    path_value,
                    source_id,
                )
            )
        if (
            not isinstance(informative_sections, list)
            or "Informative rationale" not in informative_sections
            or "Informative rationale" not in section_names
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "missing_informative_section",
                    path_value,
                    source_id,
                )
            )
        should_be_eligible = source.get("status") == "accepted"
        if source.get("eligible_for_certification") is not should_be_eligible:
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "invalid_certification_eligibility",
                    relative,
                    source_id,
                )
            )

    conformance_value = inventory.get("conformance_inputs")
    conformance_inputs = (
        [item for item in conformance_value if isinstance(item, dict)]
        if isinstance(conformance_value, list)
        else []
    )
    conformance_ids = [item.get("id") for item in conformance_inputs]
    if duplicates := duplicate_values(conformance_ids):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "duplicate_conformance_input",
                relative,
                ", ".join(duplicates),
            )
        )
    conformance_source_ids = [
        item.get("source_id") for item in conformance_inputs
    ]
    expected_conformance_ids = {
        f"CONF-{source['rfc_id']}"
        for source in sources
        if isinstance(source.get("rfc_id"), str)
    }
    if (
        set(conformance_source_ids) != set(source_by_id)
        or len(conformance_source_ids) != len(set(source_by_id))
        or set(conformance_ids) != expected_conformance_ids
    ):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "incomplete_conformance_source_coverage",
                relative,
                "Each normative source must have exactly one matching conformance input",
            )
        )
    fixture_promotion = inventory.get("fixture_promotion")
    promoted = set(
        fixture_promotion.get("current_promotions", [])
        if isinstance(fixture_promotion, dict)
        else []
    )
    corpus = load_object(
        root,
        "docs/research/corpus/manifest.json",
        BOUNDARIES_CRITERION,
        problems,
    )
    corpus_fixtures = {
        fixture.get("id"): fixture
        for fixture in corpus.get("fixtures", [])
        if isinstance(fixture, dict)
    }
    informative_boundaries = inventory.get("informative_boundaries")
    boundary_records = (
        [item for item in informative_boundaries if isinstance(item, dict)]
        if isinstance(informative_boundaries, list)
        else []
    )
    boundary_classes = [item.get("class") for item in boundary_records]
    expected_boundary_classes = {
        "research",
        "rationale-and-examples",
        "prototype",
        "unpromoted-fixture",
    }
    if (
        set(boundary_classes) != expected_boundary_classes
        or len(boundary_classes) != len(expected_boundary_classes)
        or any(item.get("conformance_allowed") is not False for item in boundary_records)
    ):
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "incomplete_informative_boundary_policy",
                relative,
                "Every informative source class must be denied exactly once",
            )
        )
    for item in conformance_inputs:
        input_id = str(item.get("id", "<unknown>"))
        source = source_by_id.get(item.get("source_id"))
        if not isinstance(source, dict):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "unknown_conformance_source",
                    relative,
                    input_id,
                )
            )
            continue
        path_value = item.get("path")
        section = item.get("section")
        if (
            path_value != source.get("path")
            or item.get("version") != source.get("version")
            or section not in source.get("normative_sections", [])
            or section in source.get("informative_sections", [])
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "informative_conformance_input",
                    relative,
                    input_id,
                )
            )
        denied_by_boundary = [
            boundary
            for boundary in boundary_records
            if isinstance(path_value, str)
            and isinstance(boundary.get("path_pattern"), str)
            and fnmatch.fnmatch(path_value, boundary["path_pattern"])
        ]
        if denied_by_boundary:
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "informative_conformance_input",
                    path_value,
                    input_id,
                )
            )
        if (
            isinstance(path_value, str)
            and path_value.startswith("docs/research/corpus/")
            and (
                input_id not in promoted
                or corpus_fixtures.get(input_id, {}).get("normative_conformance")
                is not True
            )
        ):
            problems.append(
                issue(
                    BOUNDARIES_CRITERION,
                    "unpromoted_conformance_fixture",
                    path_value,
                    input_id,
                )
            )
    if promoted:
        for fixture_id in sorted(promoted):
            if (
                fixture_id not in corpus_fixtures
                or corpus_fixtures[fixture_id].get("normative_conformance") is not True
            ):
                problems.append(
                    issue(
                        BOUNDARIES_CRITERION,
                        "invalid_fixture_promotion",
                        relative,
                        fixture_id,
                    )
                )

    rendered_relative = inventory.get("rendered_index")
    try:
        rendered = (root / str(rendered_relative)).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "incomplete_rendered_status",
                str(rendered_relative),
                str(error),
            )
        )
        rendered = ""
    required_rendered_text = {
        "Status: Informative index",
        "Version: 1.0.0",
        "Normative draft",
        "Informative",
        "not certification-eligible",
        "Supersession",
    }
    missing_rendered = sorted(
        text for text in required_rendered_text if text not in rendered
    )
    for source in sources:
        rfc_id = source.get("rfc_id")
        path_value = source.get("path")
        if not isinstance(rfc_id, str) or not isinstance(path_value, str):
            continue
        relative_link = Path(path_value).relative_to("docs").as_posix()
        supersession = source.get("supersession")
        supersession_text = (
            "none"
            if isinstance(supersession, dict)
            and supersession.get("supersedes") is None
            and supersession.get("superseded_by") is None
            else f"{supersession.get('supersedes')} -> {supersession.get('superseded_by')}"
            if isinstance(supersession, dict)
            else "<invalid>"
        )
        expected_row = (
            f"| [{rfc_id}]({relative_link}) | Normative draft | "
            f"{source.get('version')} | {source.get('status')} | "
            f"{supersession_text} |"
        )
        if expected_row not in rendered:
            missing_rendered.append(rfc_id)
    if missing_rendered:
        problems.append(
            issue(
                BOUNDARIES_CRITERION,
                "incomplete_rendered_status",
                str(rendered_relative),
                ", ".join(sorted(set(missing_rendered))),
            )
        )
    return inventory


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    for relative in sorted(PUBLIC_FILES):
        if not (root / relative).is_file():
            problems.append(
                issue(
                    CLAIMS_CRITERION
                    if "claim" in relative
                    else BOUNDARIES_CRITERION,
                    "missing_claim_boundary_file",
                    relative,
                    "Required public claim or source-boundary file is absent",
                )
            )
    validate_schema(
        root,
        "schemas/claims-ledger.schema.json",
        "policy/claims-ledger.json",
        "https://github.com/Factory-AI/testament/schemas/claims-ledger.schema.json",
        CLAIMS_CRITERION,
        problems,
    )
    validate_schema(
        root,
        "schemas/normative-sources.schema.json",
        "policy/normative-sources.json",
        "https://github.com/Factory-AI/testament/schemas/normative-sources.schema.json",
        BOUNDARIES_CRITERION,
        problems,
    )
    validate_claims(root, problems)
    validate_boundaries(root, problems)
    return problems


def report(root: Path) -> dict[str, Any]:
    problems = validate(root)
    ledger = load_object(root, "policy/claims-ledger.json", CLAIMS_CRITERION, [])
    inventory = load_object(
        root, "policy/normative-sources.json", BOUNDARIES_CRITERION, []
    )
    claims = ledger.get("claims", []) if isinstance(ledger, dict) else []
    sources = inventory.get("sources", []) if isinstance(inventory, dict) else []
    conformance = (
        inventory.get("conformance_inputs", [])
        if isinstance(inventory, dict)
        else []
    )
    return {
        "schema_version": "1.0.0",
        "criteria": [CLAIMS_CRITERION, BOUNDARIES_CRITERION],
        "status": "pass" if not problems else "fail",
        "claims_report": {
            "total": len(claims) if isinstance(claims, list) else 0,
            "architecture_shaping": sum(
                1
                for claim in claims
                if isinstance(claim, dict)
                and claim.get("category") == "architecture-shaping"
            ),
            "release_blocking": sum(
                1
                for claim in claims
                if isinstance(claim, dict)
                and claim.get("category") == "release-blocking"
            ),
            "status_counts": dict(
                sorted(
                    Counter(
                        claim.get("status")
                        for claim in claims
                        if isinstance(claim, dict)
                    ).items()
                )
            ),
            "reverse_coverage": {
                "architecture_expected": len(EXPECTED_ARCHITECTURE_POINTERS),
                "release_expected": len(EXPECTED_RELEASE_POINTERS),
            },
            "sample_traces": [
                {
                    "claim_id": claim.get("id"),
                    "source": f"{claim.get('source_path')}#{claim.get('source_pointer')}",
                    "evidence_ids": claim.get("evidence_ids"),
                    "status": claim.get("status"),
                }
                for claim in claims[:3]
                if isinstance(claim, dict)
            ],
        },
        "normative_boundary_report": {
            "inventoried_sources": len(sources) if isinstance(sources, list) else 0,
            "conformance_inputs": (
                len(conformance) if isinstance(conformance, list) else 0
            ),
            "certification_eligible": sum(
                1
                for source in sources
                if isinstance(source, dict)
                and source.get("eligible_for_certification") is True
            ),
            "promoted_fixtures": len(
                inventory.get("fixture_promotion", {}).get(
                    "current_promotions", []
                )
                if isinstance(inventory.get("fixture_promotion"), dict)
                else []
            ),
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
