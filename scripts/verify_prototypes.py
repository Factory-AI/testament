#!/usr/bin/env python3
"""Validate precommitted prototype evidence and analyzer evaluation coverage."""

from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CANONICAL_PLAN_COMMIT = "cfdf43bb49f3802137dc0ae887314ab7a8a01f58"
HISTORICAL_INVALID_PLAN_COMMIT = "cfdf43b1d85024ad5475f5c2afe41978f9fc2a01"
RECONCILED_CASES = {
    "giant-stream",
    "exact-byte",
    "compression-encryption",
    "blind-index",
    "key-rotation",
}
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
PROTOTYPE_DELIVERABLES = {
    "giant-stream": "RES-PROTOTYPE-GIANT-STREAM-001",
    "exact-byte": "RES-PROTOTYPE-EXACT-BYTE-001",
    "compression-encryption": "RES-PROTOTYPE-COMPRESSION-ENCRYPTION-001",
    "postgres-storage": "RES-PROTOTYPE-POSTGRES-STORAGE-001",
    "blind-index": "RES-PROTOTYPE-BLIND-INDEX-001",
    "key-rotation": "RES-PROTOTYPE-KEY-ROTATION-001",
    "decision-durability": "RES-PROTOTYPE-DECISION-DURABILITY-001",
    "analyzer-isolation": "RES-PROTOTYPE-ANALYZER-ISOLATION-001",
    "offline-replay": "RES-PROTOTYPE-OFFLINE-REPLAY-001",
}
BENCHMARK_DELIVERABLES = {
    case: deliverable.replace("RES-PROTOTYPE-", "RES-BENCHMARK-")
    for case, deliverable in PROTOTYPE_DELIVERABLES.items()
}
PROTOTYPE_PATHS = {
    case: f"prototypes/{case}/README.md" for case in PROTOTYPES
}
RESULT_PATH_BY_CASE = {
    case: f"docs/research/benchmarks/{case}.json" for case in PROTOTYPES
}
CLAIMS_PATH = "policy/prototype-claims.json"
REPRODUCTION_PATH = "docs/research/benchmarks/reproduction.json"
RESULT_PLAN_FIELDS = (
    "inputs",
    "sample_count",
    "budgets",
    "tolerances",
    "comparison_method",
    "acceptance_rule",
    "limitations",
    "tolerance_history",
)
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
RESULT_FILES = [RESULT_PATH_BY_CASE[case] for case in sorted(PROTOTYPES)]
EVIDENCE_FILES = [
    "docs/research/benchmarks/precommit.json",
    REPRODUCTION_PATH,
    "docs/research/analysis/evaluation-plan.md",
    "docs/research/corpus/manifest.json",
    "policy/analyzer-evaluation.json",
    CLAIMS_PATH,
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


@lru_cache(maxsize=None)
def git_object_exists(root: Path, object_name: str) -> bool:
    if not (root / ".git").exists():
        return True
    result = subprocess.run(
        ["git", "cat-file", "-e", object_name],
        cwd=root,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def git_file(root: Path, commit: str, relative: str) -> bytes | None:
    if not (root / ".git").exists():
        return None
    result = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def validate_tolerance_history(
    root: Path,
    history: Any,
    problems: list[dict[str, str]],
) -> None:
    if not isinstance(history, list):
        problems.append(
            issue(
                "VAL-READY-014",
                "missing_tolerance_history",
                "docs/research/benchmarks/precommit.json",
                "Tolerance history must be an array",
            )
        )
        return
    required = {
        "case",
        "field",
        "previous_value",
        "new_value",
        "reason",
        "reviewer",
        "reviewed_at",
        "prior_baseline_result_path",
        "prior_baseline_result_sha256",
        "rerun_result_path",
        "rerun_result_sha256",
        "decision",
    }
    for index, record in enumerate(history):
        path = f"docs/research/benchmarks/precommit.json#tolerance_history/{index}"
        valid = (
            isinstance(record, dict)
            and required <= set(record)
            and record.get("case") in PROTOTYPES
            and record.get("decision") == "approved"
            and record.get("previous_value") != record.get("new_value")
            and all(
                isinstance(record.get(field), str) and record[field]
                for field in (
                    "field",
                    "reason",
                    "reviewer",
                    "reviewed_at",
                    "prior_baseline_result_path",
                    "prior_baseline_result_sha256",
                    "rerun_result_path",
                    "rerun_result_sha256",
                )
            )
        )
        if valid:
            for prefix in ("prior_baseline", "rerun"):
                relative = record[f"{prefix}_result_path"]
                expected = record[f"{prefix}_result_sha256"]
                target = root / relative
                valid = (
                    not Path(relative).is_absolute()
                    and ".." not in Path(relative).parts
                    and len(expected) == 64
                    and target.is_file()
                    and hashlib.sha256(target.read_bytes()).hexdigest() == expected
                )
                if not valid:
                    break
        if not valid:
            problems.append(
                issue(
                    "VAL-READY-014",
                    "invalid_tolerance_change",
                    path,
                    "A tolerance change requires attributable review plus digest-bound prior-baseline and new rerun evidence",
                )
            )


def validate_claim_links(
    root: Path,
    results: dict[str, dict[str, Any]],
    problems: list[dict[str, str]],
) -> None:
    claims = load(root, CLAIMS_PATH, problems, "VAL-READY-014")
    rows = claims.get("claims")
    rows = rows if isinstance(rows, list) else []
    by_case = {
        row.get("prototype_id"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("prototype_id"), str)
    }
    if (
        claims.get("schema_version") != "1.0.0"
        or claims.get("validation_id") != "VAL-READY-014"
        or claims.get("status") != "informative-in-review"
        or claims.get("canonical_plan_commit") != CANONICAL_PLAN_COMMIT
        or len(rows) != len(PROTOTYPES)
        or set(by_case) != PROTOTYPES
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "prototype_claim_coverage_mismatch",
                CLAIMS_PATH,
                "Claim ledger must contain exactly one informative in-review row for each of the nine prototype/benchmark pairs",
            )
        )
    for case, row in by_case.items():
        result = results.get(case, {})
        required_text = (
            "claim",
            "observation",
            "inference",
            "uncertainty",
            "limitations",
            "reviewer",
            "review_status",
        )
        if (
            row.get("claim_id") != f"CLAIM-PROTOTYPE-{case.upper()}"
            or row.get("prototype_deliverable_id") != PROTOTYPE_DELIVERABLES[case]
            or row.get("benchmark_deliverable_id") != BENCHMARK_DELIVERABLES[case]
            or row.get("prototype_path") != PROTOTYPE_PATHS[case]
            or row.get("result_path") != RESULT_PATH_BY_CASE[case]
            or row.get("conclusion") != result.get("conclusion")
            or row.get("plan_commit") != CANONICAL_PLAN_COMMIT
            or any(not row.get(field) for field in required_text)
            or not (root / PROTOTYPE_PATHS[case]).is_file()
            or not (root / RESULT_PATH_BY_CASE[case]).is_file()
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "invalid_prototype_claim_link",
                    CLAIMS_PATH,
                    f"{case} does not agree with its prototype, benchmark result, conclusion, or review metadata",
                )
            )


def validate_reproduction(
    root: Path,
    plan_digest: str,
    problems: list[dict[str, str]],
) -> None:
    reproduction = load(root, REPRODUCTION_PATH, problems, "VAL-READY-014")
    rows = reproduction.get("results")
    rows = rows if isinstance(rows, list) else []
    by_case = {
        row.get("prototype_id"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("prototype_id"), str)
    }
    source_commit = reproduction.get("source_commit")
    clone_evidence = reproduction.get("clean_clone_evidence")
    report_statuses: list[bool] = []
    if (
        reproduction.get("schema_version") != "1.0.0"
        or reproduction.get("feature_id") != "reproducible-prototype-completion"
        or reproduction.get("validation_id") != "VAL-READY-014"
        or reproduction.get("status") != "pass"
        or reproduction.get("clean_clone") is not True
        or clone_evidence
        != {
            "complete_history": True,
            "independent_object_store": True,
            "worktree_clean_before_measurement": True,
        }
        or reproduction.get("plan_commit") != CANONICAL_PLAN_COMMIT
        or reproduction.get("plan_sha256") != plan_digest
        or not isinstance(source_commit, str)
        or len(source_commit) != 40
        or not git_object_exists(root, f"{source_commit}^{{commit}}")
        or len(rows) != len(PROTOTYPES)
        or set(by_case) != PROTOTYPES
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_clean_clone_reproduction",
                REPRODUCTION_PATH,
                "Clean-clone evidence must bind one resolvable source commit, the canonical plan, and exactly nine passing reruns",
            )
        )
    for case, row in by_case.items():
        raw = row.get("raw_result")
        comparison = row.get("comparison")
        baseline = load(
            root,
            RESULT_PATH_BY_CASE[case],
            problems,
            "VAL-READY-014",
        )
        plan_fields_match = (
            isinstance(raw, dict)
            and all(raw.get(field) == baseline.get(field) for field in RESULT_PLAN_FIELDS)
        )
        sample_count_matches = (
            isinstance(raw, dict)
            and raw.get("sample_count") == baseline.get("sample_count")
            and isinstance(raw.get("samples"), list)
            and len(raw["samples"]) == raw.get("sample_count")
        )
        raw_samples_valid = (
            isinstance(raw, dict)
            and valid_reproduction_samples(
                case,
                raw.get("samples"),
                raw.get("budgets"),
            )
        )
        matches = (
            baseline.get("conclusion") == "pass"
            and isinstance(raw, dict)
            and raw.get("conclusion") == "pass"
            and plan_fields_match
            and sample_count_matches
            and raw_samples_valid
        )
        report_statuses.append(matches)
        if (
            row.get("baseline_result_path") != RESULT_PATH_BY_CASE[case]
            or not isinstance(raw, dict)
            or raw.get("prototype_id") != case
            or raw.get("plan_commit") != CANONICAL_PLAN_COMMIT
            or raw.get("plan_sha256") != plan_digest
            or raw.get("conclusion") != "pass"
            or raw.get("environment", {}).get("tested_commit") != source_commit
            or not isinstance(comparison, dict)
            or comparison.get("matches") is not matches
            or comparison.get("baseline_conclusion") != baseline.get("conclusion")
            or comparison.get("rerun_conclusion") != raw.get("conclusion")
            or comparison.get("sample_count_matches") is not sample_count_matches
            or comparison.get("plan_fields_match") is not plan_fields_match
            or not matches
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "clean_clone_result_mismatch",
                    REPRODUCTION_PATH,
                    f"{case} does not reproduce its precommitted passing conclusion",
                )
            )
    expected_sample_count = sum(
        row.get("raw_result", {}).get("sample_count", 0)
        for row in rows
        if isinstance(row, dict)
    )
    if (
        reproduction.get("sample_count") != expected_sample_count
        or expected_sample_count != 27
        or reproduction.get("status")
        != ("pass" if report_statuses and all(report_statuses) else "fail")
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_reproduction_summary",
                REPRODUCTION_PATH,
                "The report summary must be recomputed from exactly 27 valid raw samples",
            )
        )


def validate_manifest_agreement(
    root: Path,
    problems: list[dict[str, str]],
) -> None:
    manifest_path = "policy/research-manifest.json"
    manifest = load(root, manifest_path, problems, "VAL-READY-014")
    rows = manifest.get("deliverables")
    rows = rows if isinstance(rows, list) else []
    by_id = {
        row.get("id"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    for case in sorted(PROTOTYPES):
        for kind, deliverable_id, artifact_path in (
            ("prototype", PROTOTYPE_DELIVERABLES[case], PROTOTYPE_PATHS[case]),
            ("benchmark", BENCHMARK_DELIVERABLES[case], RESULT_PATH_BY_CASE[case]),
        ):
            row = by_id.get(deliverable_id, {})
            locators = {
                evidence.get("locator")
                for evidence in row.get("evidence", [])
                if isinstance(evidence, dict)
            }
            artifact = row.get("artifact")
            if (
                row.get("type") != kind
                or row.get("state") != "in-review"
                or row.get("version") != "1.0.0"
                or not git_object_exists(root, f"{row.get('commit')}^{{commit}}")
                or not isinstance(artifact, dict)
                or artifact.get("path") != artifact_path
                or artifact_path not in locators
                or CLAIMS_PATH not in locators
                or REPRODUCTION_PATH not in locators
                or row.get("review", {}).get("status") != "pending"
                or row.get("decision", {}).get("status") != "pending"
            ):
                problems.append(
                    issue(
                        "VAL-READY-014",
                        "prototype_research_manifest_drift",
                        manifest_path,
                        f"{deliverable_id} does not agree with the complete in-review prototype evidence set",
                    )
                )
        prototype_directory = (root / PROTOTYPE_PATHS[case]).parent
        if (
            not prototype_directory.is_dir()
            or {path.name for path in prototype_directory.iterdir()} != {"README.md"}
            or "Informative, disposable research"
            not in (prototype_directory / "README.md").read_text(encoding="utf-8")
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "importable_or_unlabeled_prototype",
                    PROTOTYPE_PATHS[case],
                    "Each prototype directory must contain only an explicitly informative, disposable README; executable harnesses stay outside production package paths",
                )
            )


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


def valid_reproduction_samples(
    case: str,
    samples: Any,
    budgets: Any,
) -> bool:
    if not isinstance(samples, list) or not samples or not isinstance(budgets, dict):
        return False
    if case == "analyzer-isolation":
        return all(valid_analyzer_sample(sample, budgets) for sample in samples)
    if case in POSTGRES_CASES:
        return all(valid_postgres_sample(case, sample, budgets) for sample in samples)
    checks = {
        "giant-stream": lambda observation: (
            observation.get("exact_digest") is True
            and observation.get("bounded_chunk_bytes") == 65536
        ),
        "exact-byte": lambda observation: (
            observation.get("all_exact") is True
            and observation.get("classes", 0) >= 6
        ),
        "compression-encryption": lambda observation: (
            observation.get("round_trip_exact") is True
            and observation.get("tamper_rejected") is True
            and observation.get("compression_before_aead") is True
        ),
        "blind-index": lambda observation: (
            observation.get("same_scope_equality") is True
            and observation.get("cross_org_separation") is True
            and observation.get("cross_field_separation") is True
            and observation.get("rotation_changes_token") is True
        ),
        "key-rotation": lambda observation: (
            observation.get("rewrap_changed") is True
            and observation.get("payload_ciphertext_unchanged") is True
        ),
    }
    check = checks.get(case)
    if check is None:
        return False
    for sample in samples:
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
            or not check(observation)
        ):
            return False
    return True


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
    validate_tolerance_history(root, plan.get("tolerance_history"), problems)
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
    committed_plan = git_file(root, CANONICAL_PLAN_COMMIT, plan_path)
    if committed_plan is not None:
        try:
            committed_plan_digest = digest(json.loads(committed_plan))
        except json.JSONDecodeError:
            committed_plan_digest = ""
        if committed_plan_digest != plan_digest:
            problems.append(
                issue(
                    "VAL-READY-014",
                    "canonical_plan_commit_mismatch",
                    plan_path,
                    "The working plan differs from the precommitted plan at the canonical plan commit",
                )
            )
    results: dict[str, dict[str, Any]] = {}
    for relative in RESULT_FILES:
        result = load(root, relative, problems, "VAL-READY-014")
        case = result.get("prototype_id")
        if case not in PROTOTYPES:
            continue
        results[case] = result
        row = by_id.get(case, {})
        if result.get("plan_sha256") != plan_digest:
            problems.append(
                issue("VAL-READY-014", "result_plan_digest_mismatch", relative, "Result does not bind current precommit bytes")
            )
        if (
            result.get("plan_commit") != CANONICAL_PLAN_COMMIT
            or not git_object_exists(root, f"{CANONICAL_PLAN_COMMIT}^{{commit}}")
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "unresolvable_plan_commit",
                    relative,
                    "Result must bind the resolvable canonical committed precommit plan",
                )
            )
        tested_commit = result.get("environment", {}).get("tested_commit")
        if (
            not isinstance(tested_commit, str)
            or len(tested_commit) != 40
            or not git_object_exists(root, f"{tested_commit}^{{commit}}")
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "unresolvable_tested_commit",
                    relative,
                    "Result must bind a resolvable tested implementation commit",
                )
            )
        reconciliation = result.get("plan_commit_reconciliation")
        if case in RECONCILED_CASES:
            if (
                not isinstance(reconciliation, dict)
                or reconciliation.get("historical_invalid_identifier")
                != HISTORICAL_INVALID_PLAN_COMMIT
                or reconciliation.get("canonical_plan_commit")
                != CANONICAL_PLAN_COMMIT
                or reconciliation.get("preserved_samples_sha256")
                != digest(result.get("samples"))
                or not reconciliation.get("reason")
                or not reconciliation.get("reconciled_at")
            ):
                problems.append(
                    issue(
                        "VAL-READY-014",
                        "reconciled_sample_digest_mismatch",
                        relative,
                        "Historical plan-identifier reconciliation must preserve and digest-bind the original raw samples",
                    )
                )
        elif reconciliation is not None:
            problems.append(
                issue(
                    "VAL-READY-014",
                    "unexpected_plan_commit_reconciliation",
                    relative,
                    "Only results with the documented historical invalid identifier may carry reconciliation metadata",
                )
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
    validate_claim_links(root, results, problems)
    validate_reproduction(root, plan_digest, problems)
    validate_manifest_agreement(root, problems)
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
