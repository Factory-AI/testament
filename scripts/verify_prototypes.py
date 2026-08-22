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

try:
    from prototype_resources import (
        LOCAL_SCOPE,
        POSTGRES_SCOPE,
        valid_resource_sample,
    )
except ModuleNotFoundError:
    from scripts.prototype_resources import (
        LOCAL_SCOPE,
        POSTGRES_SCOPE,
        valid_resource_sample,
    )


CANONICAL_PLAN_COMMIT = "cfdf43bb49f3802137dc0ae887314ab7a8a01f58"
SUCCESSOR_PLAN_COMMIT = "0f3dce5b9418a50eb031ec3fd561282462533bd3"
SUCCESSOR_PLAN_PATH = "docs/research/benchmarks/precommit-v2.json"
V2_KEY_ROTATION_PATH = "docs/research/benchmarks/v2/key-rotation.json"
V2_DECISION_DURABILITY_PATH = (
    "docs/research/benchmarks/v2/decision-durability.json"
)
V2_REPRODUCTION_PATH = "docs/research/benchmarks/v2/reproduction.json"
HISTORICAL_INVALID_PLAN_COMMIT = "cfdf43b1d85024ad5475f5c2afe41978f9fc2a01"
V1_KEY_ROTATION_SHA256 = (
    "91a9fc76ba9852954024a925438510e7996fa471a7db94c699eedf0e88cfcc68"
)
V1_DECISION_DURABILITY_SHA256 = (
    "39b0e7685e33a80081e74d21316d1f90af8f9f2af331da01817e845453d59651"
)
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
V2_RESULT_PATH_BY_CASE = {
    case: f"docs/research/benchmarks/v2/{case}.json"
    for case in PROTOTYPES
}
V1_RESULT_SHA256_BY_CASE = {
    "giant-stream": "3f5890082d0eef097c29ad82f033ba73fc2b2fef70f90e79faa8595a252e4a48",
    "exact-byte": "9fe9ba8ded7a1a70daf0dc95d85536dd8684d2435efb04e8baffa98399fd3038",
    "compression-encryption": "dcb1beb882e731044532adc59e095fee1dfe207f8fbe493407bfd16815dc3d51",
    "postgres-storage": "08ea0e80614ba19ed2ba35b723d350f91d34303a7de88d892e5b87a714ad6522",
    "blind-index": "8e7085c8d52b695cc55b4f12cb430b3e636c18bbefa702ff42cad4e45c49a4cf",
    "key-rotation": V1_KEY_ROTATION_SHA256,
    "decision-durability": V1_DECISION_DURABILITY_SHA256,
    "analyzer-isolation": "40e815405dc429bd0bdc1954a4c618f397f41a8a847533a4bde900d64746e045",
    "offline-replay": "30ce5d01bf6e83ec56df07641609453e2d31f151c90a12b0df5f6acb0d018b08",
}
V1_REPRODUCTION_SHA256 = (
    "a275b0993c733032b11684fe64f5ab2673d558e7b1b5cb38e3e2f09460d3d59a"
)
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
    "artifact_bindings",
    "resource_budgets",
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
    "DATASET-SYNTHETIC-CORPUS-SPLIT-1.0.0",
    "DATASET-AUTHORIZED-USE-TWINS-SPLIT-1.0.0",
    "DATASET-INJECTION-MUTATIONS-SPLIT-1.0.0",
}
ANALYZER_DATASET_PATHS = {
    dataset_id: "docs/research/analysis/split-manifest.json"
    for dataset_id in ANALYZER_DATASETS
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
    "secret_disclosure_count",
    "false_evidence_acceptance_count",
    "instruction_override_count",
    "analyzer_policy_action_count",
}
RESULT_FILES = [RESULT_PATH_BY_CASE[case] for case in sorted(PROTOTYPES)]
EVIDENCE_FILES = [
    "docs/research/benchmarks/precommit.json",
    SUCCESSOR_PLAN_PATH,
    V2_KEY_ROTATION_PATH,
    V2_DECISION_DURABILITY_PATH,
    *[V2_RESULT_PATH_BY_CASE[case] for case in sorted(PROTOTYPES)],
    V2_REPRODUCTION_PATH,
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


def validate_successor_plan(
    root: Path,
    v1_plan: dict[str, Any],
    problems: list[dict[str, str]],
) -> None:
    plan = load(root, SUCCESSOR_PLAN_PATH, problems, "VAL-READY-014")
    v1_cases = {
        row.get("id"): row
        for row in v1_plan.get("cases", [])
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    v2_cases = {
        row.get("id"): row
        for row in plan.get("cases", [])
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    supersedes = plan.get("supersedes")
    preservation = plan.get("preservation")
    measurement_gate = plan.get("measurement_gate")
    remediations = plan.get("remediations")
    remediation_rows = remediations if isinstance(remediations, list) else []
    remediation_by_id = {
        row.get("finding_id"): row
        for row in remediation_rows
        if isinstance(row, dict) and isinstance(row.get("finding_id"), str)
    }
    identity_valid = (
        plan.get("schema_version") == "1.0.0"
        and plan.get("feature_id")
        == "prototype-v2-precommit-and-workload-resource-accounting"
        and plan.get("validation_ids") == ["VAL-READY-014"]
        and plan.get("version") == "2.0.0"
        and plan.get("status") == "committed-premeasurement"
        and isinstance(supersedes, dict)
        and supersedes.get("path")
        == "docs/research/benchmarks/precommit.json"
        and supersedes.get("version") == "1.0.0"
        and supersedes.get("commit") == CANONICAL_PLAN_COMMIT
        and supersedes.get("canonical_sha256") == digest(v1_plan)
        and isinstance(preservation, dict)
        and preservation.get("version_1_plan_immutable") is True
        and preservation.get("version_1_raw_results_immutable") is True
        and preservation.get("version_1_reproduction_immutable") is True
        and isinstance(measurement_gate, dict)
        and measurement_gate.get("plan_must_be_committed_before_measurement")
        is True
        and measurement_gate.get("plan_commit_must_resolve") is True
        and measurement_gate.get(
            "tested_implementation_must_descend_from_plan_commit"
        )
        is True
        and measurement_gate.get("v2_result_capture_before_plan_commit")
        == "forbidden"
        and set(remediation_by_id) == {"F-001", "F-002", "F-003"}
        and len(remediation_rows) == 3
        and "results" not in plan
    )
    if not identity_valid:
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_successor_precommit",
                SUCCESSOR_PLAN_PATH,
                "Version 2 must explicitly supersede canonical version 1, precommit F-001/F-002/F-003, and forbid precommit result capture",
            )
        )
    if (
        set(v2_cases) != PROTOTYPES
        or len(v2_cases) != len(PROTOTYPES)
        or any(
            (
                row.get("sample_count"),
                row.get("budgets"),
                row.get("tolerances"),
            )
            != (
                v1_cases.get(case, {}).get("sample_count"),
                v1_cases.get(case, {}).get("budgets"),
                v1_cases.get(case, {}).get("tolerances"),
            )
            for case, row in v2_cases.items()
        )
        or any(
            row.get("budgets", {}).get("max_process_rss_bytes") != 536870912
            for row in v2_cases.values()
        )
        or plan.get("tolerance_history") != []
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "successor_budget_or_tolerance_drift",
                SUCCESSOR_PLAN_PATH,
                "Version 2 must preserve all nine sample counts, numeric budgets, tolerances, and the 536870912-byte RSS bound",
            )
        )
    f002 = remediation_by_id.get("F-002", {})
    f002_precommit = f002.get("precommit") if isinstance(f002, dict) else {}
    f003 = remediation_by_id.get("F-003", {})
    f003_precommit = f003.get("precommit") if isinstance(f003, dict) else {}
    if (
        not isinstance(f002_precommit, dict)
        or "independently" not in str(f002.get("method", "")).lower()
        or "pre-rewrap" not in f002_precommit.get("before_capture", "")
        or "new wrapped DEK and checkpoint" not in f002_precommit.get(
            "after_capture", ""
        )
        or not {
            "independent capture method and identity",
            "pre/post payload byte counts and SHA-256 digests",
            "old/new wrapped-DEK SHA-256 digests",
            "generations [1,2]",
            "expected resume checkpoint",
        }
        <= set(f002_precommit.get("required_evidence", []))
        or not isinstance(f003_precommit, dict)
        or "backend disconnect" not in str(f003.get("method", "")).lower()
        or "without issuing ROLLBACK" not in f003_precommit.get("fault", "")
        or "terminates that exact backend" not in f003_precommit.get(
            "injection", ""
        )
        or not {
            "backend-termination fault type",
            "active transaction before injection",
            "readiness marker",
            "acknowledged termination",
            "lost client connection and nonzero client exit",
            "backend disappearance",
            "zero faulted or orphan rows",
        }
        <= set(f003_precommit.get("required_evidence", []))
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "incomplete_successor_finding_methods",
                SUCCESSOR_PLAN_PATH,
                "F-002 and F-003 must precommit independent rewrap captures and exact backend-disconnect evidence",
            )
        )
    f001 = remediation_by_id.get("F-001", {})
    local = f001.get("local_samples") if isinstance(f001, dict) else {}
    postgres = f001.get("postgres_samples") if isinstance(f001, dict) else {}
    required_fields = f001.get("required_sample_fields") if isinstance(f001, dict) else []
    if (
        not isinstance(local, dict)
        or local.get("source") != "external ps process-table snapshots"
        or "recursively discovered descendant closure" not in local.get("scope", "")
        or "coordinator" not in local.get("coordinator", "")
        or not isinstance(postgres, dict)
        or "services.yaml" not in postgres.get("isolation", "")
        or "container cgroup" not in postgres.get("source", "")
        or set(required_fields if isinstance(required_fields, list) else [])
        != {
            "accounting_version",
            "scope",
            "metric",
            "source",
            "target",
            "isolation",
            "descendants_included",
            "peak_rss_bytes",
            "budget_bytes",
            "hard_limit_bytes",
            "within_budget",
        }
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "incomplete_successor_resource_accounting",
                SUCCESSOR_PLAN_PATH,
                "F-001 must precommit isolated descendant-tree and PostgreSQL cgroup accounting with every required sample field",
            )
        )
    committed_plan = git_file(root, SUCCESSOR_PLAN_COMMIT, SUCCESSOR_PLAN_PATH)
    if not git_object_exists(root, f"{SUCCESSOR_PLAN_COMMIT}^{{commit}}"):
        problems.append(
            issue(
                "VAL-READY-014",
                "unresolvable_successor_plan_commit",
                SUCCESSOR_PLAN_PATH,
                "The version 2 plan commit must resolve before implementation or measurement",
            )
        )
    elif committed_plan is not None:
        try:
            committed_digest = digest(json.loads(committed_plan))
        except json.JSONDecodeError:
            committed_digest = ""
        if committed_digest != digest(plan):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "successor_plan_commit_mismatch",
                    SUCCESSOR_PLAN_PATH,
                    "The active version 2 plan differs from its premeasurement commit",
                )
            )


def valid_v2_resource_sample(
    sample: Any,
    budgets: dict[str, Any],
    case: str,
) -> bool:
    expected_scope = (
        POSTGRES_SCOPE
        if case in POSTGRES_CASES
        else LOCAL_SCOPE
    )
    return valid_resource_sample(sample, budgets, expected_scope)


def valid_v2_key_rotation_observation(observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    before = observation.get("pre_rewrap_payload_capture")
    after = observation.get("post_rewrap_payload_capture")
    old_wrap = observation.get("old_wrapped_dek")
    new_wrap = observation.get("new_wrapped_dek")
    if not all(
        isinstance(value, dict)
        for value in (before, after, old_wrap, new_wrap)
    ):
        return False

    def valid_digest(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    payload_equal = (
        before.get("sha256") == after.get("sha256")
        and before.get("byte_count") == after.get("byte_count")
    )
    wrapped_deks_differ = old_wrap.get("sha256") != new_wrap.get("sha256")
    return (
        before.get("capture_id") != after.get("capture_id")
        and before.get("method")
        == after.get("method")
        == "os.ReadFile persisted payload_ciphertext.bin"
        and before.get("phase") == "immediately-before-rewrap"
        and after.get("phase") == "after-new-wrapped-dek-and-checkpoint"
        and before.get("read_ordinal") == 1
        and after.get("read_ordinal") == 2
        and observation.get("operation_sequence")
        == [
            "pre_payload_capture",
            "new_wrapped_dek_persisted",
            "checkpoint_persisted",
            "post_payload_capture",
        ]
        and isinstance(before.get("byte_count"), int)
        and before["byte_count"] > 0
        and isinstance(after.get("byte_count"), int)
        and after["byte_count"] > 0
        and valid_digest(before.get("sha256"))
        and valid_digest(after.get("sha256"))
        and isinstance(old_wrap.get("byte_count"), int)
        and old_wrap["byte_count"] > 0
        and isinstance(new_wrap.get("byte_count"), int)
        and new_wrap["byte_count"] > 0
        and valid_digest(old_wrap.get("sha256"))
        and valid_digest(new_wrap.get("sha256"))
        and old_wrap.get("persisted_path")
        == "wrapped_dek.generation-1.bin"
        and new_wrap.get("persisted_path")
        == "wrapped_dek.generation-2.bin"
        and old_wrap.get("generation") == 1
        and new_wrap.get("generation") == 2
        and observation.get("generations") == [1, 2]
        and observation.get("resume_checkpoint") == 1
        and observation.get("payload_ciphertext_sha256")
        == before.get("sha256")
        and observation.get("payload_ciphertext_unchanged")
        is payload_equal
        and observation.get("rewrap_changed") is wrapped_deks_differ
        and observation.get("acceptance_recomputed") is True
        and payload_equal
        and wrapped_deks_differ
    )


def valid_v2_key_rotation_result(
    result: Any,
    successor_plan: dict[str, Any],
) -> bool:
    if not isinstance(result, dict):
        return False
    case_plan = next(
        (
            row
            for row in successor_plan.get("cases", [])
            if isinstance(row, dict) and row.get("id") == "key-rotation"
        ),
        {},
    )
    budgets = case_plan.get("budgets")
    samples = result.get("samples")
    if (
        not isinstance(budgets, dict)
        or not isinstance(samples, list)
        or not samples
    ):
        return False
    samples_valid = all(
        valid_v2_resource_sample(sample, budgets, "key-rotation")
        and valid_v2_key_rotation_observation(sample.get("observation"))
        for sample in samples
        if isinstance(sample, dict)
    ) and all(isinstance(sample, dict) for sample in samples)
    expected_conclusion = "pass" if samples_valid else "fail"
    tested_commit = result.get("environment", {}).get("tested_commit")
    return (
        result.get("schema_version") == "1.0.0"
        and result.get("feature_id")
        in {
            "key-rotation-independent-ciphertext-evidence",
            "prototype-v2-clean-clone-reconciliation",
        }
        and result.get("validation_id") == "VAL-READY-014"
        and result.get("prototype_id") == "key-rotation"
        and result.get("benchmark_id") == "key-rotation-benchmark"
        and result.get("version") == "2.0.0"
        and result.get("plan_commit") == SUCCESSOR_PLAN_COMMIT
        and result.get("plan_sha256") == digest(successor_plan)
        and all(
            result.get(field) == case_plan.get(field)
            for field in (
                "inputs",
                "sample_count",
                "budgets",
                "tolerances",
                "comparison_method",
                "acceptance_rule",
                "limitations",
            )
        )
        and result.get("tolerance_history")
        == successor_plan.get("tolerance_history")
        and result.get("sample_count") == 3
        and len(samples) == result.get("sample_count")
        and isinstance(tested_commit, str)
        and len(tested_commit) == 40
        and result.get("supersedes")
        == {
            "path": "docs/research/benchmarks/key-rotation.json",
            "version": "1.0.0",
            "sha256": V1_KEY_ROTATION_SHA256,
            "status": "superseded-evidence",
            "preserved": True,
        }
        and result.get("conclusion") == expected_conclusion == "pass"
    )


def valid_v2_decision_durability_observation(observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    marker = observation.get("readiness_marker")
    session_id = observation.get("fault_session_id")
    backend_pid = observation.get("fault_backend_pid")
    control_pid = observation.get("control_backend_pid")
    verification_pid = observation.get("verification_backend_pid")
    backend_identity_matched = (
        observation.get("observed_backend_pid") == backend_pid
        and observation.get("observed_application_name") == session_id
    )
    transaction_active = (
        observation.get("observed_xact_start_present") is True
        and observation.get("observed_transaction_state") == "active"
        and observation.get("observed_wait_event_type") == "Timeout"
        and observation.get("observed_wait_event") == "PgSleep"
    )
    client_connection_lost = (
        isinstance(observation.get("fault_client_exit_code"), int)
        and observation["fault_client_exit_code"] != 0
        and observation.get("termination_acknowledged") is True
    )
    verification_connection_fresh = (
        isinstance(control_pid, int)
        and control_pid > 0
        and isinstance(verification_pid, int)
        and verification_pid > 0
        and len({backend_pid, control_pid, verification_pid}) == 3
    )
    automatic_rollback_verified = (
        observation.get("backend_disappeared") is True
        and observation.get("faulted_rows") == 0
        and observation.get("orphan_audits") == 0
        and observation.get("orphan_receipts") == 0
    )
    return (
        observation.get("fault_type") == "postgresql-backend-termination"
        and isinstance(session_id, str)
        and session_id.startswith("testament-fault-")
        and isinstance(backend_pid, int)
        and backend_pid > 0
        and isinstance(marker, str)
        and marker == f"TESTAMENT_FAULT_READY:{backend_pid}:{session_id}"
        and observation.get("readiness_observed") is True
        and observation.get("backend_identity_matched")
        is backend_identity_matched
        and backend_identity_matched
        and observation.get("transaction_active_before_injection")
        is transaction_active
        and transaction_active
        and observation.get("termination_target_backend_pid") == backend_pid
        and observation.get("termination_target_session_id") == session_id
        and isinstance(control_pid, int)
        and control_pid > 0
        and control_pid != backend_pid
        and observation.get("termination_acknowledged") is True
        and observation.get("explicit_rollback_issued") is False
        and observation.get("client_connection_lost")
        is client_connection_lost
        and client_connection_lost
        and observation.get("backend_disappeared") is True
        and observation.get("verification_connection_fresh")
        is verification_connection_fresh
        and verification_connection_fresh
        and observation.get("automatic_rollback_verified")
        is automatic_rollback_verified
        and automatic_rollback_verified
        and observation.get("decisions") == 1
        and observation.get("audits") == 1
        and observation.get("receipts") == 1
        and observation.get("faulted_decisions") == 0
        and observation.get("faulted_audits") == 0
        and observation.get("faulted_receipts") == 0
        and observation.get("faulted_rows") == 0
        and observation.get("orphan_audits") == 0
        and observation.get("orphan_receipts") == 0
        and str(observation.get("postgres_version", "")).startswith("17.")
        and observation.get("port") == 5440
        and observation.get("acceptance_recomputed") is True
    )


def valid_v2_decision_durability_result(
    result: Any,
    successor_plan: dict[str, Any],
) -> bool:
    if not isinstance(result, dict):
        return False
    case_plan = next(
        (
            row
            for row in successor_plan.get("cases", [])
            if isinstance(row, dict)
            and row.get("id") == "decision-durability"
        ),
        {},
    )
    budgets = case_plan.get("budgets")
    samples = result.get("samples")
    if (
        not isinstance(budgets, dict)
        or not isinstance(samples, list)
        or not samples
    ):
        return False
    samples_valid = all(
        valid_v2_resource_sample(sample, budgets, "decision-durability")
        and valid_v2_decision_durability_observation(
            sample.get("observation")
        )
        for sample in samples
        if isinstance(sample, dict)
    ) and all(isinstance(sample, dict) for sample in samples)
    expected_conclusion = "pass" if samples_valid else "fail"
    tested_commit = result.get("environment", {}).get("tested_commit")
    return (
        result.get("schema_version") == "1.0.0"
        and result.get("feature_id")
        in {
            "decision-durability-disconnect-fault-evidence",
            "prototype-v2-clean-clone-reconciliation",
        }
        and result.get("validation_id") == "VAL-READY-014"
        and result.get("prototype_id") == "decision-durability"
        and result.get("benchmark_id") == "decision-durability-benchmark"
        and result.get("version") == "2.0.0"
        and result.get("plan_commit") == SUCCESSOR_PLAN_COMMIT
        and result.get("plan_sha256") == digest(successor_plan)
        and all(
            result.get(field) == case_plan.get(field)
            for field in (
                "inputs",
                "sample_count",
                "budgets",
                "tolerances",
                "comparison_method",
                "acceptance_rule",
                "limitations",
            )
        )
        and result.get("tolerance_history")
        == successor_plan.get("tolerance_history")
        and result.get("sample_count") == 3
        and len(samples) == result.get("sample_count")
        and isinstance(tested_commit, str)
        and len(tested_commit) == 40
        and result.get("supersedes")
        == {
            "path": "docs/research/benchmarks/decision-durability.json",
            "version": "1.0.0",
            "sha256": V1_DECISION_DURABILITY_SHA256,
            "status": "superseded-evidence",
            "preserved": True,
        }
        and result.get("conclusion") == expected_conclusion == "pass"
    )


def valid_v2_case_observation(case: str, observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    if case == "giant-stream":
        return (
            observation.get("exact_digest") is True
            and observation.get("bounded_chunk_bytes") == 65536
            and observation.get("bytes") == 1100055
            and observation.get("chunks") == 17
        )
    if case == "exact-byte":
        return (
            observation.get("all_exact") is True
            and observation.get("classes", 0) >= 6
        )
    if case == "compression-encryption":
        return (
            observation.get("round_trip_exact") is True
            and observation.get("tamper_rejected") is True
            and observation.get("compression_before_aead") is True
        )
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
            and str(observation.get("postgres_version", "")).startswith("17.")
            and observation.get("port") == 5440
        )
    if case == "blind-index":
        return (
            observation.get("same_scope_equality") is True
            and observation.get("cross_org_separation") is True
            and observation.get("cross_field_separation") is True
            and observation.get("rotation_changes_token") is True
            and observation.get("token_bytes") == 32
        )
    if case == "key-rotation":
        return valid_v2_key_rotation_observation(observation)
    if case == "decision-durability":
        return valid_v2_decision_durability_observation(observation)
    if case == "analyzer-isolation":
        visible = observation.get("visible_environment_variables")
        allowed = observation.get("allowed_environment_variables")
        return (
            observation.get("sanitized_environment") is True
            and isinstance(visible, list)
            and isinstance(allowed, list)
            and "PATH" in visible
            and set(visible) <= set(allowed)
            and observation.get("unexpected_environment_variables") == []
            and observation.get("isolated_working_directory") is True
            and observation.get("cpu_limit_seconds") == 1
            and observation.get("address_space_limit_enforced") is True
            and isinstance(observation.get("address_space_limit_bytes"), int)
            and 0 < observation["address_space_limit_bytes"] < 1 << 63
            and observation.get("file_descriptor_limit") == 16
            and observation.get("output_limit_enforced") is True
            and observation.get("output_limit_bytes") == 4096
            and observation.get("deadline_limit_enforced") is True
            and observation.get("deadline_seconds") == 2
            and observation.get("network_denial_proven") is False
            and observation.get("hostile_multi_tenant_isolation_proven")
            is False
            and observation.get("conclusion") == ANALYZER_CONCLUSION
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
            and str(observation.get("postgres_version", "")).startswith("17.")
            and observation.get("port") == 5440
        )
    return False


def valid_v2_result(
    case: str,
    result: Any,
    successor_plan: dict[str, Any],
) -> bool:
    if not isinstance(result, dict):
        return False
    case_plan = next(
        (
            row
            for row in successor_plan.get("cases", [])
            if isinstance(row, dict) and row.get("id") == case
        ),
        {},
    )
    budgets = case_plan.get("budgets")
    samples = result.get("samples")
    environment = result.get("environment")
    if (
        not isinstance(budgets, dict)
        or not isinstance(samples, list)
        or not isinstance(environment, dict)
    ):
        return False
    expected_environment = {
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
    samples_valid = (
        len(samples) == case_plan.get("sample_count") == 3
        and all(
            isinstance(sample, dict)
            and valid_v2_resource_sample(sample, budgets, case)
            and valid_v2_case_observation(
                case, sample.get("observation")
            )
            for sample in samples
        )
    )
    if case in POSTGRES_CASES:
        postgres = environment.get("postgres")
        postgres_valid = (
            isinstance(postgres, dict)
            and postgres.get("major") == 17
            and postgres.get("port") == 5440
            and postgres.get("service") == "postgres"
            and postgres.get("lifecycle_manifest") == "services.yaml"
            and postgres.get("healthcheck") == "pg_isready -p 5440"
            and "container cgroup" in postgres.get("resource_source", "")
        )
    else:
        postgres_valid = "postgres" not in environment
    return (
        result.get("schema_version") == "1.0.0"
        and result.get("feature_id")
        == "prototype-v2-clean-clone-reconciliation"
        and result.get("validation_id") == "VAL-READY-014"
        and result.get("prototype_id") == case
        and result.get("benchmark_id") == f"{case}-benchmark"
        and result.get("version") == "2.0.0"
        and result.get("plan_commit") == SUCCESSOR_PLAN_COMMIT
        and result.get("plan_sha256") == digest(successor_plan)
        and all(
            result.get(field) == case_plan.get(field)
            for field in (
                "inputs",
                "sample_count",
                "budgets",
                "tolerances",
                "comparison_method",
                "acceptance_rule",
                "limitations",
            )
        )
        and result.get("tolerance_history")
        == successor_plan.get("tolerance_history")
        and expected_environment <= set(environment)
        and environment.get("machine_class")
        == successor_plan.get("environment", {}).get("machine_class")
        and isinstance(environment.get("tested_commit"), str)
        and len(environment["tested_commit"]) == 40
        and postgres_valid
        and result.get("supersedes")
        == {
            "path": RESULT_PATH_BY_CASE[case],
            "version": "1.0.0",
            "sha256": V1_RESULT_SHA256_BY_CASE[case],
            "status": "superseded-evidence",
            "preserved": True,
        }
        and samples_valid
        and result.get("conclusion") == "pass"
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
        or claims.get("feature_id")
        != "prototype-v2-clean-clone-reconciliation"
        or claims.get("version") != "2.0.0"
        or claims.get("canonical_plan_commit") != SUCCESSOR_PLAN_COMMIT
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
        result = load(
            root,
            V2_RESULT_PATH_BY_CASE[case],
            problems,
            "VAL-READY-014",
        )
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
            or row.get("result_path") != V2_RESULT_PATH_BY_CASE[case]
            or row.get("conclusion") != result.get("conclusion")
            or row.get("plan_commit") != SUCCESSOR_PLAN_COMMIT
            or any(not row.get(field) for field in required_text)
            or not (root / PROTOTYPE_PATHS[case]).is_file()
            or not (root / V2_RESULT_PATH_BY_CASE[case]).is_file()
            or row.get("clean_clone_report") != V2_REPRODUCTION_PATH
            or row.get("supersedes_result")
            != {
                "path": RESULT_PATH_BY_CASE[case],
                "version": "1.0.0",
                "sha256": V1_RESULT_SHA256_BY_CASE[case],
                "status": "superseded-evidence",
            }
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


def validate_v2_reproduction(
    root: Path,
    successor_plan: dict[str, Any],
    problems: list[dict[str, str]],
) -> None:
    for case, expected_sha256 in V1_RESULT_SHA256_BY_CASE.items():
        path = root / RESULT_PATH_BY_CASE[case]
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest()
            != expected_sha256
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "modified_v1_prototype_evidence",
                    RESULT_PATH_BY_CASE[case],
                    "Version 1 prototype evidence must remain byte-for-byte immutable and queryable as superseded evidence",
                )
            )
    v1_reproduction = root / REPRODUCTION_PATH
    if (
        not v1_reproduction.is_file()
        or hashlib.sha256(v1_reproduction.read_bytes()).hexdigest()
        != V1_REPRODUCTION_SHA256
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "modified_v1_reproduction_evidence",
                REPRODUCTION_PATH,
                "Version 1 clean-clone evidence must remain byte-for-byte immutable and queryable as superseded evidence",
            )
        )

    standalone: dict[str, dict[str, Any]] = {}
    for case in sorted(PROTOTYPES):
        relative = V2_RESULT_PATH_BY_CASE[case]
        result = load(root, relative, problems, "VAL-READY-014")
        standalone[case] = result
        tested_commit = result.get("environment", {}).get("tested_commit")
        commit_valid = (
            isinstance(tested_commit, str)
            and len(tested_commit) == 40
            and git_object_exists(root, f"{tested_commit}^{{commit}}")
        )
        if commit_valid and (root / ".git").exists():
            commit_valid = (
                subprocess.run(
                    [
                        "git",
                        "merge-base",
                        "--is-ancestor",
                        SUCCESSOR_PLAN_COMMIT,
                        tested_commit,
                    ],
                    cwd=root,
                    capture_output=True,
                    check=False,
                ).returncode
                == 0
            )
        if not valid_v2_result(case, result, successor_plan) or not commit_valid:
            problems.append(
                issue(
                    "VAL-READY-014",
                    "invalid_v2_prototype_result",
                    relative,
                    f"{case} must contain exactly three valid plan-bound, externally resource-accounted version 2 samples from a committed successor",
                )
            )

    reproduction = load(
        root,
        V2_REPRODUCTION_PATH,
        problems,
        "VAL-READY-014",
    )
    rows = reproduction.get("results")
    rows = rows if isinstance(rows, list) else []
    by_case = {
        row.get("prototype_id"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("prototype_id"), str)
    }
    source_commit = reproduction.get("source_commit")
    clone_evidence = reproduction.get("clean_clone_evidence")
    source_commit_valid = (
        isinstance(source_commit, str)
        and len(source_commit) == 40
        and git_object_exists(root, f"{source_commit}^{{commit}}")
    )
    if source_commit_valid and (root / ".git").exists():
        source_commit_valid = (
            subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    SUCCESSOR_PLAN_COMMIT,
                    source_commit,
                ],
                cwd=root,
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
    if (
        reproduction.get("schema_version") != "1.0.0"
        or reproduction.get("feature_id")
        != "prototype-v2-clean-clone-reconciliation"
        or reproduction.get("validation_id") != "VAL-READY-014"
        or reproduction.get("status") != "pass"
        or reproduction.get("clean_clone") is not True
        or clone_evidence
        != {
            "complete_history": True,
            "independent_object_store": True,
            "worktree_clean_before_measurement": True,
        }
        or reproduction.get("clone_method")
        != "git clone --no-local from the candidate object database into an empty temporary directory"
        or reproduction.get("plan_commit") != SUCCESSOR_PLAN_COMMIT
        or reproduction.get("plan_sha256") != digest(successor_plan)
        or not source_commit_valid
        or len(rows) != len(PROTOTYPES)
        or set(by_case) != PROTOTYPES
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_v2_clean_clone_reproduction",
                V2_REPRODUCTION_PATH,
                "The active report must bind one complete independent clean clone, the immutable version 2 plan, one successor commit, and all nine prototype results",
            )
        )

    matches: list[bool] = []
    for case in sorted(PROTOTYPES):
        row = by_case.get(case, {})
        raw = row.get("raw_result")
        raw_result = raw if isinstance(raw, dict) else {}
        comparison = row.get("comparison")
        standalone_result = standalone.get(case, {})
        sample_count_matches = (
            isinstance(raw, dict)
            and isinstance(raw.get("samples"), list)
            and raw.get("sample_count") == len(raw["samples"]) == 3
        )
        case_plan = next(
            (
                item
                for item in successor_plan.get("cases", [])
                if isinstance(item, dict) and item.get("id") == case
            ),
            {},
        )
        plan_fields_match = isinstance(raw, dict) and all(
            raw.get(field)
            == (
                successor_plan.get("tolerance_history")
                if field == "tolerance_history"
                else case_plan.get(field)
            )
            for field in RESULT_PLAN_FIELDS
        )
        row_matches = (
            raw == standalone_result
            and valid_v2_result(case, raw, successor_plan)
            and raw_result.get("environment", {}).get("tested_commit")
            == source_commit
            and sample_count_matches
            and plan_fields_match
        )
        matches.append(row_matches)
        if (
            row.get("result_path") != V2_RESULT_PATH_BY_CASE[case]
            or row.get("supersedes_result_path")
            != RESULT_PATH_BY_CASE[case]
            or not isinstance(comparison, dict)
            or comparison.get("rerun_conclusion") != raw.get("conclusion")
            or comparison.get("rerun_conclusion")
            != raw_result.get("conclusion")
            is not sample_count_matches
            or comparison.get("plan_fields_match") is not plan_fields_match
            or comparison.get("matches") is not row_matches
            or not row_matches
        ):
            problems.append(
                issue(
                    "VAL-READY-014",
                    "v2_clean_clone_result_mismatch",
                    V2_REPRODUCTION_PATH,
                    f"{case} does not reconcile its active result, raw samples, resource provenance, plan fields, and conclusion",
                )
            )
    observed_samples = sum(
        len(row.get("raw_result", {}).get("samples", []))
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("raw_result"), dict)
        and isinstance(row["raw_result"].get("samples"), list)
    )
    expected_status = "pass" if matches and all(matches) else "fail"
    if (
        reproduction.get("sample_count") != 27
        or observed_samples != 27
        or reproduction.get("status") != expected_status
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_v2_reproduction_summary",
                V2_REPRODUCTION_PATH,
                "The active clean-clone summary must recompute exactly 27 valid samples and may not widen any budget or tolerance",
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
        active_result_path = V2_RESULT_PATH_BY_CASE[case]
        for kind, deliverable_id, artifact_path in (
            ("prototype", PROTOTYPE_DELIVERABLES[case], PROTOTYPE_PATHS[case]),
            ("benchmark", BENCHMARK_DELIVERABLES[case], active_result_path),
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
                or row.get("version") != "2.0.0"
                or not git_object_exists(root, f"{row.get('commit')}^{{commit}}")
                or not isinstance(artifact, dict)
                or artifact.get("path") != artifact_path
                or artifact_path not in locators
                or CLAIMS_PATH not in locators
                or active_result_path not in locators
                or RESULT_PATH_BY_CASE[case] not in locators
                or SUCCESSOR_PLAN_PATH not in locators
                or V2_REPRODUCTION_PATH not in locators
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
    validate_successor_plan(root, plan, problems)
    v1_key_rotation_path = root / RESULT_PATH_BY_CASE["key-rotation"]
    if (
        not v1_key_rotation_path.is_file()
        or hashlib.sha256(v1_key_rotation_path.read_bytes()).hexdigest()
        != V1_KEY_ROTATION_SHA256
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "modified_v1_key_rotation_evidence",
                RESULT_PATH_BY_CASE["key-rotation"],
                "Version 1 key-rotation evidence must remain byte-for-byte immutable",
            )
        )
    v2_key_rotation = load(
        root,
        V2_KEY_ROTATION_PATH,
        problems,
        "VAL-READY-014",
    )
    v2_tested_commit = v2_key_rotation.get("environment", {}).get(
        "tested_commit"
    )
    v2_commit_valid = (
        isinstance(v2_tested_commit, str)
        and len(v2_tested_commit) == 40
        and git_object_exists(root, f"{v2_tested_commit}^{{commit}}")
    )
    if v2_commit_valid and (root / ".git").exists():
        v2_commit_valid = (
            subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    SUCCESSOR_PLAN_COMMIT,
                    v2_tested_commit,
                ],
                cwd=root,
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
    if (
        not valid_v2_key_rotation_result(v2_key_rotation, load(
            root,
            SUCCESSOR_PLAN_PATH,
            problems,
            "VAL-READY-014",
        ))
        or not v2_commit_valid
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_v2_key_rotation_evidence",
                V2_KEY_ROTATION_PATH,
                "Version 2 key rotation requires three independently captured, recomputed, resource-bounded samples from a committed descendant of its precommit",
            )
        )
    v1_decision_path = root / RESULT_PATH_BY_CASE["decision-durability"]
    if (
        not v1_decision_path.is_file()
        or hashlib.sha256(v1_decision_path.read_bytes()).hexdigest()
        != V1_DECISION_DURABILITY_SHA256
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "modified_v1_decision_durability_evidence",
                RESULT_PATH_BY_CASE["decision-durability"],
                "Version 1 decision-durability evidence must remain byte-for-byte immutable",
            )
        )
    successor_plan = load(
        root,
        SUCCESSOR_PLAN_PATH,
        problems,
        "VAL-READY-014",
    )
    v2_decision = load(
        root,
        V2_DECISION_DURABILITY_PATH,
        problems,
        "VAL-READY-014",
    )
    decision_tested_commit = v2_decision.get("environment", {}).get(
        "tested_commit"
    )
    decision_commit_valid = (
        isinstance(decision_tested_commit, str)
        and len(decision_tested_commit) == 40
        and git_object_exists(root, f"{decision_tested_commit}^{{commit}}")
    )
    if decision_commit_valid and (root / ".git").exists():
        decision_commit_valid = (
            subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    SUCCESSOR_PLAN_COMMIT,
                    decision_tested_commit,
                ],
                cwd=root,
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
    if (
        not valid_v2_decision_durability_result(
            v2_decision,
            successor_plan,
        )
        or not decision_commit_valid
    ):
        problems.append(
            issue(
                "VAL-READY-014",
                "invalid_v2_decision_durability_evidence",
                V2_DECISION_DURABILITY_PATH,
                "Version 2 decision durability requires three exact-backend disconnect samples with recomputed rollback and resource evidence",
            )
        )
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
    validate_v2_reproduction(root, successor_plan, problems)
    validate_manifest_agreement(root, problems)
    return problems


def validate_analyzer_evaluation(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    evaluation_path = "policy/analyzer-evaluation.json"
    evaluation = load(root, evaluation_path, problems, "VAL-READY-015")
    if (
        evaluation.get("schema_version") != "1.0.0"
        or evaluation.get("feature_id")
        != "analyzer-evaluation-superseding-candidate"
        or evaluation.get("validation_ids") != ["VAL-READY-015"]
        or evaluation.get("version") != "2.0.0"
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
            "Version: 2.0.0",
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
