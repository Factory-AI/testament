#!/usr/bin/env python3
"""Validate precommitted prototype evidence and analyzer evaluation coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PROTOTYPES = {
    "giant-stream",
    "exact-byte",
    "compression-encryption",
    "postgres-storage",
    "blind-index",
    "key-rotation",
    "decision-durability",
    "analyzer-isolation",
    "offline-replay",
}
POSTGRES_CASES = {"postgres-storage", "decision-durability", "offline-replay"}
ANALYZER_FAMILIES = {
    "deterministic-rules",
    "traditional-classifier",
    "local-llm",
    "external-llm",
    "ensemble",
    "sequence",
    "longitudinal",
}
ANALYZER_DIMENSIONS = {
    "datasets",
    "fixtures",
    "metrics",
    "thresholds",
    "digests",
    "evidence_validation",
    "calibration",
    "nondeterminism",
    "abstention",
    "cost",
    "prompt_injection",
    "sovereignty",
    "source_ids",
}
ANALYZER_NESTED_DIMENSIONS = {
    "digests": {"prompt", "model", "config"},
    "calibration": {"method", "split"},
    "nondeterminism": {"class", "repeats", "comparison"},
    "abstention": {"required_cases", "metric"},
    "cost": {"measure", "hard_budget_required"},
    "prompt_injection": {"suite", "pass"},
    "sovereignty": {"profiles", "attestation_required"},
}
ANALYZER_DATASETS = {
    "DATASET-SYNTHETIC-CORPUS-1.0.0",
    "DATASET-AUTHORIZED-USE-TWINS-1.0.0",
    "DATASET-INJECTION-MUTATIONS-1.0.0",
}
ANALYZER_DATASET_PATHS = {
    "DATASET-SYNTHETIC-CORPUS-1.0.0": "docs/research/corpus/manifest.json",
    "DATASET-AUTHORIZED-USE-TWINS-1.0.0": "docs/research/corpus/manifest.json",
    "DATASET-INJECTION-MUTATIONS-1.0.0": (
        "docs/research/analysis/evaluation-plan.md#prompt-injection-suite"
    ),
}
ANALYZER_SOURCES = {
    "SRC-NIST-AML-2025",
    "SRC-OWASP-LLM01-2025",
    "SRC-SKLEARN-CALIBRATION-1.9",
}
CORE_ANALYZER_METRICS = {
    "evidence_reference_precision",
    "evidence_reference_recall",
    "schema_valid_rate",
    "cross_org_reference_count",
    "unauthorized_capability_count",
    "injection_control_success_rate",
    "abstention_on_unanswerable",
    "cost_budget_overrun_count",
}
RESULT_FILES = [
    f"docs/research/benchmarks/{case}.json" for case in sorted(PROTOTYPES)
]
EVIDENCE_FILES = [
    "docs/research/benchmarks/precommit.json",
    "docs/research/analysis/evaluation-plan.md",
    "docs/research/corpus/manifest.json",
    "policy/analyzer-evaluation.json",
    "policy/research-manifest.json",
    *RESULT_FILES,
]
ANALYZER_CONCLUSION = (
    "POSIX subprocess limits bound CPU, address space, descriptors, "
    "environment, working directory, time, and output, but do not "
    "prove network denial; plain subprocess isolation is rejected "
    "as a hostile multi-tenant isolation boundary."
)


def issue(criterion: str, code: str, path: str, message: str) -> dict[str, str]:
    remediation = (
        "make verify-analyzer-evaluation"
        if criterion == "VAL-READY-015"
        else "make verify-prototypes"
    )
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": remediation,
    }


def load(root: Path, relative: str, problems: list[dict[str, str]], criterion: str) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(issue(criterion, "invalid_or_missing_json", relative, str(error)))
        return {}
    if not isinstance(value, dict):
        problems.append(issue(criterion, "invalid_json_shape", relative, "Root must be an object"))
        return {}
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item) for item in value)
    )


def valid_threshold(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"operator", "value"}
        and value.get("operator") in {"<=", ">=", "=="}
        and isinstance(value.get("value"), (int, float))
        and not isinstance(value.get("value"), bool)
        and math.isfinite(value["value"])
    )


def valid_analyzer_sample(
    sample: Any,
    budgets: dict[str, Any],
) -> bool:
    if not isinstance(sample, dict):
        return False
    elapsed = sample.get("elapsed_ms")
    rss = sample.get("process_max_rss_bytes")
    if (
        not isinstance(elapsed, (int, float))
        or elapsed > budgets.get("max_elapsed_ms", -1)
        or not isinstance(rss, int)
        or rss > budgets.get("max_process_rss_bytes", -1)
    ):
        return False
    observation = sample.get("observation")
    if not isinstance(observation, dict):
        return False
    visible = observation.get("visible_environment_variables")
    allowed = observation.get("allowed_environment_variables")
    address_space = observation.get("address_space_limit_bytes")
    output_bytes = observation.get("output_bytes")
    output_probe_bytes = observation.get("output_probe_bytes")
    environment_lists_valid = (
        isinstance(visible, list)
        and all(isinstance(name, str) for name in visible)
        and isinstance(allowed, list)
        and all(isinstance(name, str) for name in allowed)
    )
    return (
        observation.get("sanitized_environment") is True
        and environment_lists_valid
        and "PATH" in visible
        and set(visible) <= set(allowed)
        and observation.get("unexpected_environment_variables") == []
        and observation.get("isolated_working_directory") is True
        and observation.get("cpu_limit_seconds") == 1
        and observation.get("address_space_limit_enforced") is True
        and isinstance(address_space, int)
        and 0 < address_space < 1 << 63
        and observation.get("file_descriptor_limit") == 16
        and observation.get("output_limit_enforced") is True
        and observation.get("output_limit_bytes") == 4096
        and isinstance(output_bytes, int)
        and 0 < output_bytes <= 4096
        and isinstance(output_probe_bytes, int)
        and 0 < output_probe_bytes <= 4096
        and observation.get("deadline_limit_enforced") is True
        and observation.get("deadline_seconds") == 2
        and observation.get("network_denial_proven") is False
        and observation.get("hostile_multi_tenant_isolation_proven") is False
        and observation.get("conclusion") == ANALYZER_CONCLUSION
    )


def valid_postgres_sample(
    case: str,
    sample: Any,
    budgets: dict[str, Any],
) -> bool:
    if not isinstance(sample, dict):
        return False
    elapsed = sample.get("elapsed_ms")
    rss = sample.get("process_max_rss_bytes")
    observation = sample.get("observation")
    if (
        not isinstance(elapsed, (int, float))
        or elapsed > budgets.get("max_elapsed_ms", -1)
        or not isinstance(rss, int)
        or rss > budgets.get("max_process_rss_bytes", -1)
        or not isinstance(observation, dict)
        or not str(observation.get("postgres_version", "")).startswith("17.")
        or observation.get("port") != 5440
    ):
        return False
    if case == "postgres-storage":
        explain_lines = observation.get("explain_lines")
        return (
            observation.get("rows") == 200
            and observation.get("partitions") == 2
            and observation.get("ciphertext_nonempty_rows") == 200
            and observation.get("content_column") == "ciphertext"
            and observation.get("content_column_type") == "bytea"
            and observation.get("forbidden_plaintext_columns") == 0
            and observation.get("ciphertext_only_columns") is True
            and observation.get("partition_pruning") is True
            and observation.get("executed_partition") == "chunks_2026_08"
            and observation.get("pruned_partition") == "chunks_2026_09"
            and isinstance(explain_lines, list)
            and any("chunks_2026_08" in line for line in explain_lines)
            and not any("chunks_2026_09" in line for line in explain_lines)
        )
    if case == "decision-durability":
        return (
            observation.get("decisions") == 1
            and observation.get("audits") == 1
            and observation.get("receipts") == 1
            and observation.get("faulted_decisions") == 0
            and observation.get("faulted_audits") == 0
            and observation.get("faulted_receipts") == 0
            and observation.get("faulted_rows") == 0
            and observation.get("orphan_audits") == 0
            and observation.get("orphan_receipts") == 0
        )
    if case == "offline-replay":
        pinned = observation.get("pinned_replay_digests")
        late = observation.get("late_revision")
        history = observation.get("run_history")
        return (
            observation.get("runs") == 3
            and observation.get("recorded_replay_equal") is True
            and isinstance(pinned, list)
            and len(pinned) == 2
            and len(set(pinned)) == 1
            and observation.get("late_revision_changed") is True
            and isinstance(late, dict)
            and late.get("id") == 3
            and late.get("supersedes") == 2
            and late.get("includes_late_event") is True
            and isinstance(history, list)
            and [row.get("id") for row in history] == [1, 2, 3]
            and [row.get("supersedes") for row in history] == [None, 1, 2]
            and observation.get("history_preserved") is True
        )
    return False


def validate_prototype_evidence(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    plan_path = "docs/research/benchmarks/precommit.json"
    plan = load(root, plan_path, problems, "VAL-READY-014")
    cases = plan.get("cases", [])
    if not isinstance(cases, list):
        cases = []
    by_id = {
        row.get("id"): row
        for row in cases
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    missing = sorted(PROTOTYPES - set(by_id))
    extra = sorted(set(by_id) - PROTOTYPES)
    if missing or extra:
        problems.append(
            issue(
                "VAL-READY-014",
                "prototype_coverage_mismatch",
                plan_path,
                f"Missing={missing}; extra={extra}",
            )
        )
    if not isinstance(plan.get("tolerance_history"), list):
        problems.append(
            issue("VAL-READY-014", "missing_tolerance_history", plan_path, "Tolerance history must be an array")
        )
    for case, row in by_id.items():
        required = {
            "inputs", "sample_count", "budgets", "tolerances",
            "comparison_method", "acceptance_rule", "limitations",
        }
        if required - set(row) or not isinstance(row.get("sample_count"), int):
            problems.append(
                issue("VAL-READY-014", "incomplete_precommit", plan_path, f"{case} omits required precommit fields")
            )
    plan_digest = digest(plan)
    for relative in RESULT_FILES:
        result = load(root, relative, problems, "VAL-READY-014")
        case = result.get("prototype_id")
        if case not in PROTOTYPES:
            continue
        row = by_id.get(case, {})
        if result.get("plan_sha256") != plan_digest:
            problems.append(
                issue("VAL-READY-014", "result_plan_digest_mismatch", relative, "Result does not bind current precommit bytes")
            )
        if not isinstance(result.get("plan_commit"), str) or len(result["plan_commit"]) != 40:
            problems.append(
                issue("VAL-READY-014", "invalid_plan_commit", relative, "Result must bind a 40-character plan commit")
            )
        if result.get("sample_count") != row.get("sample_count") or len(result.get("samples", [])) != row.get("sample_count"):
            problems.append(
                issue("VAL-READY-014", "wrong_sample_count", relative, "Raw sample count differs from the precommit")
            )
        for field in ("inputs", "budgets", "tolerances", "comparison_method", "acceptance_rule", "limitations"):
            if result.get(field) != row.get(field):
                problems.append(
                    issue("VAL-READY-014", "result_plan_field_mismatch", relative, f"Result changed precommitted {field}")
                )
        if result.get("tolerance_history") != plan.get("tolerance_history"):
            problems.append(
                issue("VAL-READY-014", "tolerance_history_mismatch", relative, "Result omits reviewed tolerance history")
            )
        if result.get("conclusion") != "pass":
            problems.append(
                issue("VAL-READY-014", "prototype_conclusion_failed", relative, "Prototype did not meet its precommitted acceptance rule")
            )
        if case == "analyzer-isolation":
            environment = result.get("environment")
            required_environment = {
                "os",
                "architecture",
                "cpu_count",
                "memory_bytes",
                "python",
                "go",
                "docker",
                "tested_commit",
                "machine_class",
            }
            tested_commit = (
                environment.get("tested_commit")
                if isinstance(environment, dict)
                else None
            )
            environment_valid = (
                isinstance(environment, dict)
                and required_environment <= set(environment)
                and isinstance(tested_commit, str)
                and len(tested_commit) == 40
            )
            samples = result.get("samples")
            samples_valid = (
                isinstance(samples, list)
                and bool(samples)
                and all(
                    valid_analyzer_sample(sample, row.get("budgets", {}))
                    for sample in samples
                )
            )
            if not environment_valid or not samples_valid:
                problems.append(
                    issue(
                        "VAL-READY-014",
                        "invalid_analyzer_isolation_observation",
                        relative,
                        "Every analyzer sample must bind the machine and enforce ambient, CPU, address-space, descriptor, output, deadline, and honest isolation bounds",
                    )
                )
        if case in POSTGRES_CASES:
            postgres = result.get("environment", {}).get("postgres", {})
            if (
                postgres.get("major") != 17
                or postgres.get("port") != 5440
                or postgres.get("service") != "postgres"
                or postgres.get("healthcheck") != "pg_isready -p 5440"
                or postgres.get("lifecycle_manifest") != "services.yaml"
            ):
                problems.append(
                    issue("VAL-READY-014", "invalid_postgres_environment", relative, "PostgreSQL evidence must bind version 17, port 5440, and declared lifecycle")
                )
            samples = result.get("samples")
            if (
                not isinstance(samples, list)
                or not samples
                or not all(
                    valid_postgres_sample(case, sample, row.get("budgets", {}))
                    for sample in samples
                )
            ):
                problems.append(
                    issue(
                        "VAL-READY-014",
                        "invalid_postgres_observation",
                        relative,
                        "Every PostgreSQL sample must preserve its version, port, budget, and case-specific durability evidence",
                    )
                )
    return problems


def validate_analyzer_evaluation(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    evaluation_path = "policy/analyzer-evaluation.json"
    evaluation = load(root, evaluation_path, problems, "VAL-READY-015")
    if (
        evaluation.get("schema_version") != "1.0.0"
        or evaluation.get("feature_id") != "analyzer-family-evaluation-plan"
        or evaluation.get("validation_ids") != ["VAL-READY-015"]
        or evaluation.get("version") != "1.0.0"
        or evaluation.get("status") != "in-review"
    ):
        problems.append(
            issue(
                "VAL-READY-015",
                "invalid_analyzer_plan_identity",
                evaluation_path,
                "Analyzer plan identity, version, validation scope, or review state drifted",
            )
        )
    datasets = evaluation.get("datasets")
    dataset_rows = datasets if isinstance(datasets, list) else []
    dataset_by_id = {
        row.get("id"): row
        for row in dataset_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if (
        set(dataset_by_id) != ANALYZER_DATASETS
        or len(dataset_by_id) != len(dataset_rows)
    ):
        problems.append(
            issue(
                "VAL-READY-015",
                "analyzer_dataset_coverage_mismatch",
                evaluation_path,
                f"Expected {sorted(ANALYZER_DATASETS)}, found {sorted(dataset_by_id)}",
            )
        )
    corpus_path = "docs/research/corpus/manifest.json"
    corpus = load(root, corpus_path, problems, "VAL-READY-015")
    corpus_fixtures = corpus.get("fixtures")
    corpus_rows = corpus_fixtures if isinstance(corpus_fixtures, list) else []
    corpus_fixture_ids = {
        row.get("id")
        for row in corpus_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    for dataset_id, row in dataset_by_id.items():
        fixture_ids = row.get("fixture_ids")
        dataset_path = row.get("path")
        bounded_path = (
            dataset_path.split("#", 1)[0]
            if isinstance(dataset_path, str)
            else ""
        )
        if (
            not nonempty_strings(fixture_ids)
            or not set(fixture_ids) <= corpus_fixture_ids
            or dataset_path != ANALYZER_DATASET_PATHS.get(dataset_id)
            or not bounded_path
            or not (root / bounded_path).is_file()
            or any(
                not row.get(field)
                for field in ("split", "leakage_control", "limitations")
            )
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "invalid_analyzer_dataset_mapping",
                    evaluation_path,
                    f"{dataset_id} must bind fixtures, split, leakage control, limitations, and a repository path",
                )
            )
    global_thresholds = evaluation.get("global_thresholds")
    if (
        not isinstance(global_thresholds, dict)
        or set(global_thresholds) != CORE_ANALYZER_METRICS
        or not all(valid_threshold(value) for value in global_thresholds.values())
    ):
        problems.append(
            issue(
                "VAL-READY-015",
                "analyzer_metric_threshold_mismatch",
                evaluation_path,
                "Global analyzer metrics require fixed numeric thresholds",
            )
        )
    families = evaluation.get("families", [])
    if not isinstance(families, list):
        families = []
    family_by_id = {
        row.get("family"): row
        for row in families
        if isinstance(row, dict) and isinstance(row.get("family"), str)
    }
    if (
        set(family_by_id) != ANALYZER_FAMILIES
        or len(family_by_id) != len(families)
    ):
        problems.append(
            issue(
                "VAL-READY-015",
                "missing_analyzer_family",
                evaluation_path,
                f"Expected {sorted(ANALYZER_FAMILIES)}, found {sorted(family_by_id)}",
            )
        )
    for family, row in family_by_id.items():
        missing_dimensions = ANALYZER_DIMENSIONS - set(row)
        for dimension, keys in ANALYZER_NESTED_DIMENSIONS.items():
            value = row.get(dimension)
            if not isinstance(value, dict) or keys - set(value):
                missing_dimensions.add(dimension)
        if missing_dimensions:
            problems.append(
                issue(
                    "VAL-READY-015",
                    "incomplete_analyzer_dimension",
                    evaluation_path,
                    f"{family} omits or incompletely defines {sorted(missing_dimensions)}",
                )
            )
        family_datasets = row.get("datasets")
        if (
            not nonempty_strings(family_datasets)
            or not set(family_datasets) <= set(dataset_by_id)
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "invalid_analyzer_dataset_mapping",
                    evaluation_path,
                    f"{family} must map to registered datasets",
                )
            )
        fixtures = row.get("fixtures")
        if (
            not nonempty_strings(fixtures)
            or not set(fixtures) <= corpus_fixture_ids
            or (
                nonempty_strings(family_datasets)
                and not set(fixtures)
                <= {
                    fixture_id
                    for dataset_id in family_datasets
                    for fixture_id in dataset_by_id.get(dataset_id, {}).get(
                        "fixture_ids", []
                    )
                    if isinstance(fixture_id, str)
                }
            )
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "invalid_analyzer_fixture_mapping",
                    evaluation_path,
                    f"{family} must map to registered synthetic corpus fixture IDs",
                )
            )
        metrics = row.get("metrics")
        thresholds = row.get("thresholds")
        metric_ids = set(metrics) if nonempty_strings(metrics) else set()
        metric_count = len(metrics) if isinstance(metrics, list) else 0
        threshold_ids = set(thresholds) if isinstance(thresholds, dict) else set()
        if (
            len(metric_ids) != metric_count
            or not CORE_ANALYZER_METRICS <= metric_ids
            or metric_ids != threshold_ids
            or not isinstance(thresholds, dict)
            or not all(valid_threshold(value) for value in thresholds.values())
            or (
                isinstance(global_thresholds, dict)
                and any(
                    thresholds.get(metric) != global_thresholds.get(metric)
                    for metric in CORE_ANALYZER_METRICS
                )
            )
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "analyzer_metric_threshold_mismatch",
                    evaluation_path,
                    f"{family} requires one fixed numeric threshold for each unique metric",
                )
            )
    source_ids: set[str] = set()
    sources = evaluation.get("sources")
    source_rows = sources if isinstance(sources, list) else []
    for source in source_rows:
        if not isinstance(source, dict):
            continue
        source_ids.add(str(source.get("id")))
        parsed = urlparse(str(source.get("source_url", "")))
        required = {"publisher", "title", "version_or_date", "accessed_at", "claim_supported"}
        if parsed.scheme != "https" or not parsed.netloc or any(not source.get(field) for field in required):
            problems.append(
                issue("VAL-READY-015", "incomplete_analyzer_source", evaluation_path, f"Incomplete source {source.get('id')}")
            )
    if source_ids != ANALYZER_SOURCES or len(source_ids) != len(source_rows):
        problems.append(
            issue("VAL-READY-015", "analyzer_source_coverage_mismatch", evaluation_path, "Required reviewed sources are missing")
        )
    for family, row in family_by_id.items():
        family_sources = row.get("source_ids")
        if (
            not nonempty_strings(family_sources)
            or not set(family_sources) <= source_ids
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "analyzer_source_coverage_mismatch",
                    evaluation_path,
                    f"{family} must map to complete source records",
                )
            )
    prose_path = "docs/research/analysis/evaluation-plan.md"
    try:
        prose = (root / prose_path).read_text(encoding="utf-8")
    except OSError as error:
        problems.append(
            issue("VAL-READY-015", "invalid_analyzer_plan_prose", prose_path, str(error))
        )
    else:
        required_prose = {
            "Status: In review",
            "Version: 1.0.0",
            "Validation: `VAL-READY-015`",
            "Machine matrix: [`policy/analyzer-evaluation.json`]",
        }
        if not all(value in prose for value in required_prose):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "analyzer_plan_prose_drift",
                    prose_path,
                    "Prose version, review state, validation ID, or matrix link drifted",
                )
            )
        source_urls = {
            source.get("source_url")
            for source in source_rows
            if isinstance(source, dict)
            and isinstance(source.get("source_url"), str)
        }
        if any(source_url not in prose for source_url in source_urls):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "analyzer_plan_prose_drift",
                    prose_path,
                    "The prose plan does not cite every machine-readable source URL",
                )
            )
    research_manifest_path = "policy/research-manifest.json"
    research_manifest = load(
        root, research_manifest_path, problems, "VAL-READY-015"
    )
    manifest_deliverables = research_manifest.get("deliverables")
    deliverable_rows = (
        manifest_deliverables if isinstance(manifest_deliverables, list) else []
    )
    analyzer_entries = [
        row
        for row in deliverable_rows
        if isinstance(row, dict)
        and row.get("id") == "RES-STUDY-ANALYZER-EVALUATION-001"
    ]
    if len(analyzer_entries) != 1:
        problems.append(
            issue(
                "VAL-READY-015",
                "analyzer_research_manifest_drift",
                research_manifest_path,
                "Analyzer evaluation deliverable must appear exactly once",
            )
        )
    else:
        entry = analyzer_entries[0]
        artifact = entry.get("artifact")
        artifact = artifact if isinstance(artifact, dict) else {}
        owner = entry.get("owner")
        owner = owner if isinstance(owner, dict) else {}
        review = entry.get("review")
        review = review if isinstance(review, dict) else {}
        evidence_locators = {
            item.get("locator")
            for item in entry.get("evidence", [])
            if isinstance(item, dict)
        }
        if (
            entry.get("state") != "in-review"
            or entry.get("version") != evaluation.get("version")
            or artifact.get("path") != prose_path
            or prose_path not in evidence_locators
            or evaluation_path not in evidence_locators
            or owner.get("identity") not in str(evaluation.get("owner"))
            or review.get("reviewer")
            != "non-author analysis, security, and privacy reviewer"
            or review.get("status") != "pending"
            or evaluation.get("reviewer")
            != "non-author analysis, security, and privacy reviewer pending"
        ):
            problems.append(
                issue(
                    "VAL-READY-015",
                    "analyzer_research_manifest_drift",
                    research_manifest_path,
                    "Manifest version, review state, artifacts, or evidence disagree with the analyzer plan",
                )
            )
    return problems


def validate(root: Path) -> list[dict[str, str]]:
    return [
        *validate_prototype_evidence(root),
        *validate_analyzer_evaluation(root),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--criterion",
        choices=["VAL-READY-014", "VAL-READY-015"],
        help="Report one criterion while preserving the shared verifier implementation.",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    criteria = ["VAL-READY-014", "VAL-READY-015"]
    if args.criterion == "VAL-READY-014":
        criteria = [args.criterion]
        problems = validate_prototype_evidence(root)
    elif args.criterion == "VAL-READY-015":
        criteria = [args.criterion]
        problems = validate_analyzer_evaluation(root)
    else:
        problems = validate(root)
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criteria": criteria,
                "status": "pass" if not problems else "fail",
                "prototype_count": len(PROTOTYPES),
                "analyzer_family_count": len(ANALYZER_FAMILIES),
                "problems": problems,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
