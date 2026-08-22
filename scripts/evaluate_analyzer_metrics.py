#!/usr/bin/env python3
"""Deterministically evaluate versioned analyzer metrics over canonical records."""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal, ROUND_HALF_EVEN
import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable


EVALUATOR_VERSION = "1.0.0"
def canonical_json(value: Any, *, pretty: bool = False) -> bytes:
    separators = None if pretty else (",", ":")
    text = json.dumps(
        value,
        ensure_ascii=True,
        indent=2 if pretty else None,
        separators=separators,
        sort_keys=True,
    )
    return (text + ("\n" if pretty else "")).encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def decimal(value: Any) -> Decimal:
    if isinstance(value, bool):
        return Decimal(int(value))
    return Decimal(str(value))


def eligible_records(metric: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = metric["eligibility"]
    required = metric["required_inputs"]
    selected = []
    for record in records:
        if record.get("eligible", True) is not True:
            continue
        if record.get("status") not in rules["included_statuses"]:
            continue
        if record.get("excluded_reason") in rules["excluded_reasons"]:
            continue
        if rules["abstention"] == "exclude" and record.get("abstained", False):
            continue
        if rules["abstention"] == "only" and not record.get("abstained", False):
            continue
        if not all(record.get(field) is True for field in rules.get("required_true", [])):
            continue
        if not all(field in record for field in required):
            continue
        selected.append(record)
    return selected


def ratio(numerator: Decimal, denominator: Decimal) -> tuple[Decimal | None, dict[str, Any]]:
    if denominator == 0:
        return None, {"denominator": 0, "numerator": number_component(numerator)}
    return numerator / denominator, {
        "denominator": number_component(denominator),
        "numerator": number_component(numerator),
    }


def number_component(value: Decimal) -> int | str:
    if value == value.to_integral_value():
        return int(value)
    return format(value.normalize(), "f")


def field_precision(
    records: list[dict[str, Any]], predicted: str, expected: str
) -> tuple[Decimal | None, dict[str, Any]]:
    predicted_rows = [record for record in records if record[predicted]]
    correct = sum(1 for record in predicted_rows if record[expected])
    return ratio(Decimal(correct), Decimal(len(predicted_rows)))


def field_recall(
    records: list[dict[str, Any]], predicted: str, expected: str
) -> tuple[Decimal | None, dict[str, Any]]:
    expected_rows = [record for record in records if record[expected]]
    correct = sum(1 for record in expected_rows if record[predicted])
    return ratio(Decimal(correct), Decimal(len(expected_rows)))


def sum_ratio(
    records: list[dict[str, Any]], numerator: str, denominator: str
) -> tuple[Decimal | None, dict[str, Any]]:
    numerator_value = sum((decimal(record[numerator]) for record in records), Decimal(0))
    denominator_value = sum(
        (decimal(record[denominator]) for record in records), Decimal(0)
    )
    return ratio(numerator_value, denominator_value)


def boolean_rate(
    records: list[dict[str, Any]], field: str
) -> tuple[Decimal | None, dict[str, Any]]:
    return ratio(
        Decimal(sum(1 for record in records if record[field])),
        Decimal(len(records)),
    )


def false_positive_rate(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    negatives = [record for record in records if not record["expected_positive"]]
    false_positives = sum(1 for record in negatives if record["predicted_positive"])
    return ratio(Decimal(false_positives), Decimal(len(negatives)))


def count_true(
    records: list[dict[str, Any]], field: str
) -> tuple[Decimal, dict[str, Any]]:
    attempts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        attempts[
            (
                str(record.get("split", "unspecified")),
                str(record["attempt_id"]),
            )
        ].append(record)
    count = sum(
        1 for repeats in attempts.values() if any(record[field] for record in repeats)
    )
    return Decimal(count), {"attempts": len(attempts), "count": count}


def injection_success(
    records: list[dict[str, Any]], outcomes: list[str]
) -> tuple[Decimal | None, dict[str, Any]]:
    attempts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        attempts[
            (
                str(record.get("split", "unspecified")),
                str(record.get("attempt_id", f"row-{index}")),
            )
        ].append(record)
    failures = {
        attempt_id
        for attempt_id, repeats in attempts.items()
        if any(
            any(record[outcome] for outcome in outcomes)
            for record in repeats
        )
    }
    denominator = len(attempts)
    numerator = denominator - len(failures)
    value, components = ratio(Decimal(numerator), Decimal(denominator))
    components["distinct_prohibited_outcome_failure_attempts"] = len(failures)
    return value, components


def repeat_digest_match(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for record in records:
        groups[
            (
                str(record.get("split", "unspecified")),
                str(record["repeat_group_id"]),
            )
        ].append(str(record["output_digest"]))
    comparable = [digests for digests in groups.values() if len(digests) >= 2]
    matches = sum(1 for digests in comparable if len(set(digests)) == 1)
    return ratio(Decimal(matches), Decimal(len(comparable)))


def nearest_rank_percentile(
    records: list[dict[str, Any]], field: str, percentile: Decimal
) -> tuple[Decimal | None, dict[str, Any]]:
    values = sorted(decimal(record[field]) for record in records)
    if not values:
        return None, {"count": 0, "percentile": format(percentile, "f")}
    rank = max(1, math.ceil(float(percentile * len(values))))
    return values[rank - 1], {
        "count": len(values),
        "percentile": format(percentile, "f"),
        "rank": rank,
    }


def average_precision(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    ordered = sorted(
        records,
        key=lambda record: (
            -decimal(record["score"]),
            str(record["sample_id"]),
        ),
    )
    positives = sum(1 for record in ordered if record["expected_positive"])
    if positives == 0:
        return None, {"positive_count": 0, "sample_count": len(ordered)}
    true_positives = 0
    sum_precision = Decimal(0)
    for rank, record in enumerate(ordered, start=1):
        if record["expected_positive"]:
            true_positives += 1
            sum_precision += Decimal(true_positives) / Decimal(rank)
    return sum_precision / Decimal(positives), {
        "positive_count": positives,
        "sample_count": len(ordered),
    }


def macro_class_metric(
    records: list[dict[str, Any]], *, precision: bool
) -> tuple[Decimal | None, dict[str, Any]]:
    classes = sorted(
        {str(record["class_label"]) for record in records}
        | {str(record["predicted_class"]) for record in records}
    )
    predicted_counts = Counter(str(record["predicted_class"]) for record in records)
    expected_counts = Counter(str(record["class_label"]) for record in records)
    correct_counts = Counter(
        str(record["class_label"])
        for record in records
        if str(record["class_label"]) == str(record["predicted_class"])
    )
    values = []
    for class_id in classes:
        denominator = (
            predicted_counts[class_id] if precision else expected_counts[class_id]
        )
        if denominator == 0:
            return None, {"class_count": len(classes), "undefined_class": class_id}
        values.append(Decimal(correct_counts[class_id]) / Decimal(denominator))
    if not values:
        return None, {"class_count": 0}
    return sum(values, Decimal(0)) / Decimal(len(values)), {"class_count": len(values)}


def mean_squared_error(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    if not records:
        return None, {"sample_count": 0}
    total = sum(
        (
            (decimal(record["confidence"]) - decimal(record["expected_positive"])) ** 2
            for record in records
        ),
        Decimal(0),
    )
    return total / Decimal(len(records)), {"sample_count": len(records)}


def expected_calibration_error(
    records: list[dict[str, Any]], bins: int
) -> tuple[Decimal | None, dict[str, Any]]:
    if not records:
        return None, {"bin_count": bins, "sample_count": 0}
    grouped: list[list[dict[str, Any]]] = [[] for _ in range(bins)]
    for record in records:
        confidence = decimal(record["confidence"])
        index = min(bins - 1, int(confidence * bins))
        grouped[index].append(record)
    total = Decimal(0)
    nonempty = 0
    for rows in grouped:
        if not rows:
            continue
        nonempty += 1
        average_confidence = sum(
            (decimal(row["confidence"]) for row in rows), Decimal(0)
        ) / Decimal(len(rows))
        accuracy = sum(
            (decimal(row["expected_positive"]) for row in rows), Decimal(0)
        ) / Decimal(len(rows))
        total += (
            Decimal(len(rows))
            / Decimal(len(records))
            * abs(average_confidence - accuracy)
        )
    return total, {
        "bin_count": bins,
        "nonempty_bins": nonempty,
        "sample_count": len(records),
    }


def selective_risk(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    selected = [record for record in records if not record["abstained"]]
    errors = sum(1 for record in selected if not record["correct"])
    return ratio(Decimal(errors), Decimal(len(selected)))


def mean_field(
    records: list[dict[str, Any]], field: str
) -> tuple[Decimal | None, dict[str, Any]]:
    if not records:
        return None, {"sample_count": 0}
    value = sum((decimal(record[field]) for record in records), Decimal(0))
    return value / Decimal(len(records)), {"sample_count": len(records)}


def run_variance(
    records: list[dict[str, Any]],
) -> tuple[Decimal | None, dict[str, Any]]:
    groups: dict[tuple[str, str], list[Decimal]] = defaultdict(list)
    for record in records:
        groups[
            (
                str(record.get("split", "unspecified")),
                str(record["repeat_group_id"]),
            )
        ].append(decimal(record["score"]))
    comparable = [values for values in groups.values() if len(values) >= 2]
    if not comparable:
        return None, {"repeat_group_count": 0}
    variances = []
    for values in comparable:
        average = sum(values, Decimal(0)) / Decimal(len(values))
        variances.append(
            sum(((value - average) ** 2 for value in values), Decimal(0))
            / Decimal(len(values))
        )
    return sum(variances, Decimal(0)) / Decimal(len(variances)), {
        "repeat_group_count": len(comparable)
    }


def count_budget_overruns(
    records: list[dict[str, Any]],
) -> tuple[Decimal, dict[str, Any]]:
    attempts: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        attempts[
            (
                str(record.get("split", "unspecified")),
                str(record["attempt_id"]),
            )
        ].append(record)
    count = sum(
        1
        for repeats in attempts.values()
        if any(
            decimal(record["cost_actual"]) > decimal(record["cost_budget"])
            for record in repeats
        )
    )
    return Decimal(count), {"attempts": len(attempts), "count": count}


def compute_base(
    metric: dict[str, Any], records: list[dict[str, Any]]
) -> tuple[Decimal | None, dict[str, Any]]:
    rows = eligible_records(metric, records)
    formula = metric["formula"]
    operation = formula["operation"]
    field = formula.get("field")
    operations: dict[str, Callable[[], tuple[Decimal | None, dict[str, Any]]]] = {
        "binary_precision": lambda: field_precision(
            rows, formula["predicted_field"], formula["expected_field"]
        ),
        "binary_recall": lambda: field_recall(
            rows, formula["predicted_field"], formula["expected_field"]
        ),
        "false_positive_rate": lambda: false_positive_rate(rows),
        "sum_ratio": lambda: sum_ratio(
            rows, formula["numerator_field"], formula["denominator_field"]
        ),
        "boolean_rate": lambda: boolean_rate(rows, str(field)),
        "count_true": lambda: count_true(rows, str(field)),
        "injection_control_success_rate": lambda: injection_success(
            rows, list(formula["prohibited_outcomes"])
        ),
        "repeat_digest_match_rate": lambda: repeat_digest_match(rows),
        "nearest_rank_percentile": lambda: nearest_rank_percentile(
            rows, str(field), decimal(formula["percentile"])
        ),
        "average_precision": lambda: average_precision(rows),
        "macro_class_precision": lambda: macro_class_metric(rows, precision=True),
        "macro_class_recall": lambda: macro_class_metric(rows, precision=False),
        "brier_score": lambda: mean_squared_error(rows),
        "expected_calibration_error": lambda: expected_calibration_error(
            rows, int(formula["bins"])
        ),
        "selective_risk": lambda: selective_risk(rows),
        "mean": lambda: mean_field(rows, str(field)),
        "population_run_variance": lambda: run_variance(rows),
        "cost_budget_overrun_count": lambda: count_budget_overruns(rows),
    }
    if operation not in operations:
        raise ValueError(f"unknown metric formula operation: {operation}")
    value, components = operations[operation]()
    components["eligible_records"] = len(rows)
    return value, components


def aggregate_family(
    metric: dict[str, Any],
    records: list[dict[str, Any]],
    split_values: list[Decimal | None],
) -> tuple[Decimal | None, dict[str, Any]]:
    operation = metric["family_aggregation"]["operation"]
    if operation == "macro_mean_defined_splits":
        values = [value for value in split_values if value is not None]
        if not values:
            return None, {"aggregation": operation}
        return sum(values, Decimal(0)) / Decimal(len(values)), {
            "aggregation": operation,
            "defined_splits": len(values),
        }
    if operation in {
        "micro_recompute",
        "sum_split_counts",
        "weighted_mean_by_eligible_records",
        "pooled_nearest_rank_percentile",
        "pooled_repeat_groups",
        "pooled_population_variance",
    }:
        value, components = compute_base(metric, records)
        components["aggregation"] = operation
        return value, components
    raise ValueError(f"unknown family aggregation operation: {operation}")


def rounded_value(metric: dict[str, Any], value: Decimal | None) -> int | str | None:
    if value is None:
        return None
    if metric["value_type"] == "integer":
        return int(value)
    places = int(metric["rounding"]["decimal_places"])
    quantum = Decimal(1).scaleb(-places)
    return format(value.quantize(quantum, rounding=ROUND_HALF_EVEN), f".{places}f")


def accepted(metric: dict[str, Any], value: Decimal | None) -> bool:
    if value is None:
        return False
    threshold = decimal(metric["acceptance"]["value"])
    operator = metric["acceptance"]["operator"]
    return {
        "==": value == threshold,
        ">=": value >= threshold,
        "<=": value <= threshold,
    }[operator]


def comparison_value(metric: dict[str, Any], value: Decimal) -> int | str:
    if metric["value_type"] == "integer":
        return int(value)
    return format(value, "f")


def evaluate_metric(
    metric: dict[str, Any], records: list[dict[str, Any]]
) -> dict[str, Any]:
    records_by_split: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        records_by_split[str(record.get("split", "unspecified"))].append(record)
    split_results = []
    split_values = []
    for split in sorted(records_by_split):
        value, components = compute_base(metric, records_by_split[split])
        split_values.append(value)
        split_results.append(
            {
                "components": components,
                "split": split,
                "status": "defined" if value is not None else "undefined",
                "value": rounded_value(metric, value),
            }
        )
    value, components = aggregate_family(metric, records, split_values)
    result = {
        "accepted": accepted(metric, value),
        "components": components,
        "metric_id": metric["id"],
        "split_results": split_results,
        "status": "defined" if value is not None else "undefined",
        "unit": metric["unit"],
        "value": rounded_value(metric, value),
    }
    if value is None:
        result["undefined_reason"] = metric["undefined_result"]["reason"]
    else:
        result["comparison_value"] = comparison_value(metric, value)
    return result


def evaluate(
    registry: dict[str, Any],
    records: list[dict[str, Any]],
    metric_ids: list[str],
    *,
    family: str,
) -> dict[str, Any]:
    metrics_by_id = {metric["id"]: metric for metric in registry["metrics"]}
    if len(metrics_by_id) != len(registry["metrics"]):
        raise ValueError("duplicate metric IDs")
    unknown = sorted(set(metric_ids) - set(metrics_by_id))
    if unknown:
        raise ValueError(f"unknown metric IDs: {unknown}")
    result = {
        "evaluator_version": EVALUATOR_VERSION,
        "family": family,
        "metrics": [
            evaluate_metric(metrics_by_id[metric_id], records)
            for metric_id in sorted(metric_ids)
        ],
        "registry_version": registry["version"],
        "schema_version": "1.0.0",
    }
    result["result_digest"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    request = json.loads(args.input.read_text(encoding="utf-8"))
    result = evaluate(
        registry,
        request["records"],
        request["metric_ids"],
        family=request["family"],
    )
    sys.stdout.buffer.write(canonical_json(result, pretty=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
