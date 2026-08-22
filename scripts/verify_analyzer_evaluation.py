#!/usr/bin/env python3
"""Verify deterministic analyzer fixtures, digests, groups, and split assignments."""

from __future__ import annotations

from collections import Counter, defaultdict
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


CRITERION = "VAL-READY-015"


def load_generator():
    path = Path(__file__).with_name("generate_analyzer_evaluation.py")
    specification = importlib.util.spec_from_file_location(
        "testament_generate_analyzer_evaluation", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load generator from {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GENERATE = load_generator()
EVIDENCE_FILES = [
    GENERATE.CORPUS_MANIFEST_PATH,
    GENERATE.ANALYZER_PLAN_PATH,
    GENERATE.INJECTION_MANIFEST_PATH,
    GENERATE.SPLIT_MANIFEST_PATH,
    *(GENERATE.injection_path(seed) for seed in GENERATE.SEEDS),
]


def issue(code: str, path: str, message: str) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": CRITERION,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": "make generate-analyzer-evaluation && make verify-analyzer-evaluation",
    }


def load_object(
    root: Path,
    relative: str,
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(issue("invalid_or_missing_json", relative, str(error)))
        return {}
    if not isinstance(value, dict):
        problems.append(issue("invalid_json_shape", relative, "Root must be an object"))
        return {}
    return value


def duplicate_values(values: list[Any]) -> list[str]:
    return sorted(
        str(value)
        for value, count in Counter(values).items()
        if count > 1
    )


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_injection_manifest(
    root: Path,
    corpus_fixture_ids: set[str],
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    relative = GENERATE.INJECTION_MANIFEST_PATH
    manifest = load_object(root, relative, problems)
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("version") != GENERATE.INJECTION_DATASET_VERSION
        or manifest.get("feature_id")
        != "analyzer-evaluation-deterministic-fixtures-and-splits"
        or manifest.get("status") != "informative-research"
        or manifest.get("classes") != list(GENERATE.INJECTION_CLASSES)
        or manifest.get("seed_range")
        != {"first": 1401, "last": 1420, "step": 1}
    ):
        problems.append(
            issue(
                "injection_manifest_identity_drift",
                relative,
                "Injection manifest identity, version, classes, or seed range drifted",
            )
        )
    generator = manifest.get("generator")
    if (
        not isinstance(generator, dict)
        or generator.get("version") != GENERATE.GENERATOR_VERSION
        or generator.get("implementation")
        != "scripts/generate_analyzer_evaluation.py"
        or generator.get("runtime") != "Python 3 standard library only"
    ):
        problems.append(
            issue(
                "injection_generator_drift",
                relative,
                "The pinned standard-library generator identity or version drifted",
            )
        )
    rows = manifest.get("cases")
    case_rows = rows if isinstance(rows, list) else []
    case_ids = [
        row.get("id") for row in case_rows if isinstance(row, dict)
    ]
    seeds = [
        row.get("seed") for row in case_rows if isinstance(row, dict)
    ]
    duplicate_ids = duplicate_values(case_ids)
    duplicate_seeds = duplicate_values(seeds)
    if duplicate_ids or duplicate_seeds:
        problems.append(
            issue(
                "duplicate_injection_case",
                relative,
                f"Duplicate IDs={duplicate_ids}, seeds={duplicate_seeds}",
            )
        )
    expected_ids = {GENERATE.case_id(seed) for seed in GENERATE.SEEDS}
    actual_ids = {value for value in case_ids if isinstance(value, str)}
    missing_ids = sorted(expected_ids - actual_ids)
    if missing_ids or len(case_rows) < len(GENERATE.SEEDS):
        problems.append(
            issue(
                "missing_injection_case",
                relative,
                f"Missing required cases: {missing_ids}",
            )
        )
    extra_ids = sorted(actual_ids - expected_ids)
    if extra_ids or len(case_rows) > len(GENERATE.SEEDS):
        problems.append(
            issue(
                "unknown_injection_case",
                relative,
                f"Unknown or excess cases: {extra_ids}",
            )
        )

    fixture_root = root / GENERATE.INJECTION_FIXTURE_ROOT
    expected_fixture_paths = {
        GENERATE.injection_path(seed) for seed in GENERATE.SEEDS
    }
    actual_fixture_paths = (
        {
            path.relative_to(root).as_posix()
            for path in fixture_root.iterdir()
            if path.is_file()
        }
        if fixture_root.is_dir()
        else set()
    )
    unknown_fixture_paths = sorted(actual_fixture_paths - expected_fixture_paths)
    if unknown_fixture_paths:
        problems.append(
            issue(
                "unknown_injection_fixture",
                GENERATE.INJECTION_FIXTURE_ROOT,
                f"Unknown fixture files: {unknown_fixture_paths}",
            )
        )

    actual_fixture_bytes: dict[int, bytes] = {}
    for row in case_rows:
        if not isinstance(row, dict) or not isinstance(row.get("seed"), int):
            problems.append(
                issue("invalid_injection_case", relative, "Every case must be an object with an integer seed")
            )
            continue
        seed = row["seed"]
        if seed not in GENERATE.SEEDS:
            continue
        injection_class = GENERATE.class_for_seed(seed)
        expected_path = GENERATE.injection_path(seed)
        expected_source = GENERATE.CLASS_SOURCE_FIXTURE[injection_class]
        if row.get("source_fixture") not in corpus_fixture_ids:
            problems.append(
                issue(
                    "unknown_source_fixture",
                    relative,
                    f"{row.get('id')} references {row.get('source_fixture')}",
                )
            )
        if (
            row.get("id") != GENERATE.case_id(seed)
            or row.get("class") != injection_class
            or row.get("path") != expected_path
            or row.get("source_fixture") != expected_source
            or row.get("prohibited_outcomes")
            != list(GENERATE.PROHIBITED_OUTCOMES)
            or not row.get("expected_inert_behavior")
        ):
            problems.append(
                issue(
                    "invalid_injection_case",
                    relative,
                    f"Seed {seed} has drifted class, path, source, expectation, or prohibited outcomes",
                )
            )
        try:
            fixture = (root / expected_path).read_bytes()
        except OSError as error:
            problems.append(issue("missing_injection_case", expected_path, str(error)))
            continue
        actual_fixture_bytes[seed] = fixture
        digest = hashlib.sha256(fixture).hexdigest()
        if (
            row.get("byte_count") != len(fixture)
            or row.get("sha256") != digest
            or not valid_sha256(row.get("sha256"))
        ):
            problems.append(
                issue(
                    "injection_digest_drift",
                    expected_path,
                    f"Seed {seed} byte count or SHA-256 does not match the committed fixture",
                )
            )

    if set(actual_fixture_bytes) == set(GENERATE.SEEDS):
        digest = hashlib.sha256()
        for seed in GENERATE.SEEDS:
            digest.update(actual_fixture_bytes[seed])
        if (
            manifest.get("aggregate_dataset_sha256") != digest.hexdigest()
            or manifest.get("dataset_byte_count")
            != sum(len(content) for content in actual_fixture_bytes.values())
        ):
            problems.append(
                issue(
                    "aggregate_injection_digest_drift",
                    relative,
                    "Aggregate dataset byte count or SHA-256 drifted",
                )
            )
    return manifest


def validate_split_manifest(
    root: Path,
    corpus_fixture_ids: set[str],
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    relative = GENERATE.SPLIT_MANIFEST_PATH
    manifest = load_object(root, relative, problems)
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("version") != GENERATE.SPLIT_MANIFEST_VERSION
        or manifest.get("feature_id")
        != "analyzer-evaluation-deterministic-fixtures-and-splits"
        or manifest.get("status") != "informative-research"
        or manifest.get("families") != list(GENERATE.FAMILIES)
        or manifest.get("injection_partition") != "holdout"
        or not manifest.get("scope")
    ):
        problems.append(
            issue(
                "split_manifest_identity_drift",
                relative,
                "Split manifest identity, version, families, status, or injection partition drifted",
            )
        )
    if manifest.get("algorithm") != GENERATE.SPLIT_ALGORITHM:
        problems.append(
            issue(
                "split_algorithm_drift",
                relative,
                "Hash input, byte order, modulus, bucket mapping, or algorithm version drifted",
            )
        )
    required_partitions = manifest.get("required_partitions")
    if (
        not isinstance(required_partitions, dict)
        or set(required_partitions) != set(GENERATE.FAMILIES)
        or any(
            required_partitions.get(family) != list(GENERATE.PARTITIONS)
            for family in GENERATE.FAMILIES
        )
    ):
        problems.append(
            issue(
                "required_partition_drift",
                relative,
                "Every analyzer family must require development, calibration, and holdout",
            )
        )

    rows = manifest.get("cases")
    case_rows = rows if isinstance(rows, list) else []
    case_ids = [
        row.get("case_id") for row in case_rows if isinstance(row, dict)
    ]
    duplicate_case_ids = duplicate_values(case_ids)
    if duplicate_case_ids:
        problems.append(
            issue(
                "duplicate_split_case",
                relative,
                f"Duplicate split case IDs: {duplicate_case_ids}",
            )
        )
    expected_case_ids = {
        GENERATE.corpus_case_id(fixture_id)
        for fixture_id in GENERATE.CORPUS_CASE_FIXTURES
    } | {GENERATE.case_id(seed) for seed in GENERATE.SEEDS}
    actual_case_ids = {value for value in case_ids if isinstance(value, str)}
    if expected_case_ids - actual_case_ids:
        problems.append(
            issue(
                "missing_split_case",
                relative,
                f"Missing cases: {sorted(expected_case_ids - actual_case_ids)}",
            )
        )
    if actual_case_ids - expected_case_ids:
        problems.append(
            issue(
                "unknown_split_case",
                relative,
                f"Unknown cases: {sorted(actual_case_ids - expected_case_ids)}",
            )
        )

    expected_injection_ids = {GENERATE.case_id(seed) for seed in GENERATE.SEEDS}
    cases_by_group: dict[str, list[str]] = defaultdict(list)
    family_partitions: dict[str, set[str]] = defaultdict(set)
    group_partition_by_id: dict[str, str] = {}
    group_rows_value = manifest.get("groups")
    group_rows = group_rows_value if isinstance(group_rows_value, list) else []
    group_ids = [
        row.get("group_id") for row in group_rows if isinstance(row, dict)
    ]
    duplicate_group_ids = duplicate_values(group_ids)
    if duplicate_group_ids:
        partitions_by_duplicate: dict[str, set[Any]] = defaultdict(set)
        for row in group_rows:
            if isinstance(row, dict) and row.get("group_id") in duplicate_group_ids:
                partitions_by_duplicate[str(row.get("group_id"))].add(row.get("partition"))
        if any(len(partitions) > 1 for partitions in partitions_by_duplicate.values()):
            problems.append(
                issue(
                    "group_leakage",
                    relative,
                    f"One group has multiple partitions: {dict(partitions_by_duplicate)}",
                )
            )
        else:
            problems.append(
                issue(
                    "duplicate_split_group",
                    relative,
                    f"Duplicate groups: {duplicate_group_ids}",
                )
            )

    for row in group_rows:
        if not isinstance(row, dict) or not isinstance(row.get("group_id"), str):
            problems.append(issue("invalid_split_group", relative, "Every group requires a string ID"))
            continue
        group_id = row["group_id"]
        partition, bucket, digest = GENERATE.split_bucket(group_id)
        if (
            row.get("partition") != partition
            or row.get("bucket") != bucket
            or row.get("sha256") != digest
            or row.get("hash_input") != GENERATE.split_hash_input(group_id).hex()
        ):
            problems.append(
                issue(
                    "invalid_split_assignment",
                    relative,
                    f"{group_id} does not match the declared hash algorithm",
                )
            )
        group_partition_by_id[group_id] = str(row.get("partition"))

    for row in case_rows:
        if not isinstance(row, dict):
            problems.append(issue("invalid_split_case", relative, "Every case must be an object"))
            continue
        case = row.get("case_id")
        group_id = row.get("group_id")
        source_fixture = row.get("source_fixture")
        family_applicability = row.get("family_applicability")
        if not isinstance(case, str) or not isinstance(group_id, str):
            problems.append(issue("invalid_split_case", relative, "Case and group IDs must be strings"))
            continue
        cases_by_group[group_id].append(case)
        if (
            not isinstance(family_applicability, list)
            or len(family_applicability) != len(set(family_applicability))
            or not set(family_applicability) <= set(GENERATE.FAMILIES)
        ):
            problems.append(
                issue(
                    "invalid_family_applicability",
                    relative,
                    f"{case} has unknown or duplicate family applicability",
                )
            )
            family_applicability = []
        case_kind = row.get("case_kind")
        if case_kind == "corpus":
            if source_fixture not in corpus_fixture_ids:
                problems.append(
                    issue(
                        "unknown_source_fixture",
                        relative,
                        f"{case} references unknown corpus fixture {source_fixture}",
                    )
                )
        elif case_kind == "injection":
            if source_fixture not in expected_injection_ids:
                problems.append(
                    issue(
                        "unknown_source_fixture",
                        relative,
                        f"{case} references unknown injection fixture {source_fixture}",
                    )
                )
            if group_partition_by_id.get(group_id) != "holdout":
                problems.append(
                    issue(
                        "injection_partition_leakage",
                        relative,
                        f"{case} is assigned outside holdout",
                    )
                )
        else:
            problems.append(
                issue("invalid_split_case", relative, f"{case} has invalid case_kind")
            )
        partition = group_partition_by_id.get(group_id)
        if partition:
            for family in family_applicability:
                family_partitions[family].add(partition)

    group_by_id = {
        row["group_id"]: row
        for row in group_rows
        if isinstance(row, dict) and isinstance(row.get("group_id"), str)
    }
    if set(group_by_id) != set(cases_by_group):
        problems.append(
            issue(
                "group_case_coverage_mismatch",
                relative,
                "Every case group must have exactly one assignment and no orphan group",
            )
        )
    for group_id, case_group_ids in cases_by_group.items():
        group = group_by_id.get(group_id)
        if (
            not isinstance(group, dict)
            or group.get("case_ids") != sorted(case_group_ids)
        ):
            problems.append(
                issue(
                    "group_case_coverage_mismatch",
                    relative,
                    f"{group_id} case membership drifted",
                )
            )

    for family in GENERATE.FAMILIES:
        missing = set(GENERATE.PARTITIONS) - family_partitions[family]
        if missing:
            problems.append(
                issue(
                    "empty_required_partition",
                    relative,
                    f"{family} has no applicable cases in {sorted(missing)}",
                )
            )

    twin_rows = [
        row
        for row in case_rows
        if isinstance(row, dict)
        and row.get("source_fixture") in GENERATE.AUTHORIZED_TWIN_FIXTURES
    ]
    twin_groups = {
        row.get("group_id") for row in twin_rows if isinstance(row.get("group_id"), str)
    }
    twin_partitions = {
        group_partition_by_id.get(group_id) for group_id in twin_groups
    }
    if (
        len(twin_rows) != len(GENERATE.AUTHORIZED_TWIN_FIXTURES)
        or len(twin_groups) != 1
        or len(twin_partitions) != 1
    ):
        problems.append(
            issue(
                "authorized_twin_group_leakage",
                relative,
                "Paired authorized-use twins must share one group and partition",
            )
        )

    bindings = manifest.get("bindings")
    bindings = bindings if isinstance(bindings, dict) else {}
    try:
        corpus_digest = hashlib.sha256(
            (root / GENERATE.CORPUS_MANIFEST_PATH).read_bytes()
        ).hexdigest()
        injection_digest = hashlib.sha256(
            (root / GENERATE.INJECTION_MANIFEST_PATH).read_bytes()
        ).hexdigest()
    except OSError as error:
        problems.append(issue("split_binding_drift", relative, str(error)))
    else:
        if bindings != {
            "analyzer_plan": {
                "path": GENERATE.ANALYZER_PLAN_PATH,
                "sha256": GENERATE.BASE_ANALYZER_PLAN_SHA256,
            },
            "corpus_manifest": {
                "path": GENERATE.CORPUS_MANIFEST_PATH,
                "sha256": corpus_digest,
            },
            "injection_manifest": {
                "path": GENERATE.INJECTION_MANIFEST_PATH,
                "sha256": injection_digest,
            },
        }:
            problems.append(
                issue(
                    "split_binding_drift",
                    relative,
                    "Split inputs do not bind the current corpus and injection manifests",
                )
            )
    return manifest


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    corpus = load_object(root, GENERATE.CORPUS_MANIFEST_PATH, problems)
    corpus_rows = corpus.get("fixtures")
    corpus_rows = corpus_rows if isinstance(corpus_rows, list) else []
    corpus_fixture_ids = {
        row.get("id")
        for row in corpus_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if not set(GENERATE.CORPUS_CASE_FIXTURES) <= corpus_fixture_ids:
        problems.append(
            issue(
                "unknown_source_fixture",
                GENERATE.CORPUS_MANIFEST_PATH,
                "Required analyzer source fixtures are absent from the corpus manifest",
            )
        )
    validate_injection_manifest(root, corpus_fixture_ids, problems)
    validate_split_manifest(
        root, corpus_fixture_ids, problems
    )
    try:
        expected = GENERATE.expected_files(root)
    except (OSError, ValueError, KeyError) as error:
        problems.append(
            issue(
                "analyzer_generation_failed",
                "scripts/generate_analyzer_evaluation.py",
                str(error),
            )
        )
    else:
        for relative, expected_bytes in expected.items():
            try:
                actual = (root / relative).read_bytes()
            except OSError:
                continue
            if actual != expected_bytes:
                problems.append(
                    issue(
                        "generated_analyzer_evidence_drift",
                        relative,
                        "Committed bytes do not match clean regeneration",
                    )
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    problems = validate(root)
    report = {
        "criteria": [CRITERION],
        "families": len(GENERATE.FAMILIES),
        "injection_cases": len(GENERATE.SEEDS),
        "problems": problems,
        "schema_version": "1.0.0",
        "status": "pass" if not problems else "fail",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
