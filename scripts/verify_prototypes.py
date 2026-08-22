#!/usr/bin/env python3
"""Validate precommitted prototype evidence and analyzer evaluation coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
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
}
RESULT_FILES = [
    f"docs/research/benchmarks/{case}.json" for case in sorted(PROTOTYPES)
]
EVIDENCE_FILES = [
    "docs/research/benchmarks/precommit.json",
    "policy/analyzer-evaluation.json",
    *RESULT_FILES,
]
ANALYZER_CONCLUSION = (
    "POSIX subprocess limits bound CPU, address space, descriptors, "
    "environment, working directory, time, and output, but do not "
    "prove network denial; plain subprocess isolation is rejected "
    "as a hostile multi-tenant isolation boundary."
)


def issue(criterion: str, code: str, path: str, message: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": "make verify-prototypes",
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


def validate(root: Path) -> list[dict[str, str]]:
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
                or not str(postgres.get("lifecycle_manifest", "")).endswith("/services.yaml")
            ):
                problems.append(
                    issue("VAL-READY-014", "invalid_postgres_environment", relative, "PostgreSQL evidence must bind version 17, port 5440, and declared lifecycle")
                )
    evaluation_path = "policy/analyzer-evaluation.json"
    evaluation = load(root, evaluation_path, problems, "VAL-READY-015")
    families = evaluation.get("families", [])
    if not isinstance(families, list):
        families = []
    family_by_id = {
        row.get("family"): row
        for row in families
        if isinstance(row, dict) and isinstance(row.get("family"), str)
    }
    if set(family_by_id) != ANALYZER_FAMILIES:
        problems.append(
            issue(
                "VAL-READY-015",
                "missing_analyzer_family",
                evaluation_path,
                f"Expected {sorted(ANALYZER_FAMILIES)}, found {sorted(family_by_id)}",
            )
        )
    for family, row in family_by_id.items():
        if ANALYZER_DIMENSIONS - set(row):
            problems.append(
                issue("VAL-READY-015", "incomplete_analyzer_dimension", evaluation_path, f"{family} omits {sorted(ANALYZER_DIMENSIONS - set(row))}")
            )
    source_ids: set[str] = set()
    for source in evaluation.get("sources", []):
        if not isinstance(source, dict):
            continue
        source_ids.add(str(source.get("id")))
        parsed = urlparse(str(source.get("source_url", "")))
        required = {"publisher", "title", "version_or_date", "accessed_at", "claim_supported"}
        if parsed.scheme != "https" or not parsed.netloc or any(not source.get(field) for field in required):
            problems.append(
                issue("VAL-READY-015", "incomplete_analyzer_source", evaluation_path, f"Incomplete source {source.get('id')}")
            )
    if source_ids != {"SRC-NIST-AML-2025", "SRC-OWASP-LLM01-2025", "SRC-SKLEARN-CALIBRATION-1.9"}:
        problems.append(
            issue("VAL-READY-015", "analyzer_source_coverage_mismatch", evaluation_path, "Required reviewed sources are missing")
        )
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
                "criteria": ["VAL-READY-014", "VAL-READY-015"],
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
