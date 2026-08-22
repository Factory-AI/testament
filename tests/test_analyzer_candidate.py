from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    specification = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / f"{name}.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


VERIFY = load_script("verify_analyzer_candidate")


class AnalyzerCandidateTest(unittest.TestCase):
    def copy_evidence(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.EVIDENCE_FILES:
            source = ROOT / relative
            if not source.is_file():
                continue
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def mutate_json(self, root: Path, relative: str, mutation) -> None:
        path = root / relative
        document = (
            json.loads(path.read_text(encoding="utf-8"))
            if path.is_file()
            else {}
        )
        mutation(document)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_repository_candidate_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_relaxed_zero_failure_threshold_fails(self) -> None:
        root = self.copy_evidence()

        def relax(plan):
            plan["global_thresholds"]["injection_control_success_rate"] = {
                "operator": ">=",
                "value": 0.95,
            }

        self.mutate_json(root, VERIFY.PLAN_PATH, relax)
        self.assertIn("relaxed_zero_failure_threshold", self.codes(root))

    def test_omitted_safety_metric_fails(self) -> None:
        root = self.copy_evidence()

        def omit(plan):
            family = plan["families"][0]
            family["metrics"].remove("unauthorized_capability_count")
            family["thresholds"].pop("unauthorized_capability_count")

        self.mutate_json(root, VERIFY.PLAN_PATH, omit)
        self.assertIn("omitted_safety_metric", self.codes(root))

    def test_empty_partition_fails(self) -> None:
        root = self.copy_evidence()

        def empty_partition(manifest):
            calibration = {
                group["group_id"]
                for group in manifest["groups"]
                if group["partition"] == "calibration"
            }
            for case in manifest["cases"]:
                if case["group_id"] in calibration:
                    case["family_applicability"] = []

        self.mutate_json(
            root,
            "docs/research/analysis/split-manifest.json",
            empty_partition,
        )
        self.assertIn("empty_required_partition", self.codes(root))

    def test_split_overlap_fails(self) -> None:
        root = self.copy_evidence()

        def overlap(manifest):
            duplicate = dict(manifest["groups"][0])
            duplicate["partition"] = (
                "holdout"
                if duplicate["partition"] != "holdout"
                else "development"
            )
            manifest["groups"].append(duplicate)

        self.mutate_json(
            root,
            "docs/research/analysis/split-manifest.json",
            overlap,
        )
        self.assertIn("group_leakage", self.codes(root))

    def test_stale_artifact_digest_fails(self) -> None:
        root = self.copy_evidence()

        def stale(plan):
            plan.setdefault("artifact_catalog", {})["split_manifest"] = {
                "path": "docs/research/analysis/split-manifest.json",
                "sha256": "0" * 64,
                "version": "1.0.0",
            }

        self.mutate_json(root, VERIFY.PLAN_PATH, stale)
        self.assertIn("stale_analyzer_artifact_digest", self.codes(root))

    def test_missing_metric_definition_fails(self) -> None:
        root = self.copy_evidence()

        def remove_metric(registry):
            registry["metrics"] = [
                metric
                for metric in registry["metrics"]
                if metric["id"] != "instruction_override_count"
            ]

        self.mutate_json(
            root, "policy/analyzer-metric-registry.json", remove_metric
        )
        self.assertIn("missing_metric_definition", self.codes(root))

    def test_nonpositive_budget_fails(self) -> None:
        root = self.copy_evidence()

        def invalidate(plan):
            plan["families"][0]["resource_budgets"] = {
                "limits": {
                    "wall_time": {
                        "applicability": "required",
                        "maximum": 0,
                        "unit": "milliseconds_per_attempt",
                    }
                }
            }

        self.mutate_json(root, VERIFY.PLAN_PATH, invalidate)
        self.assertIn("nonpositive_resource_budget", self.codes(root))

    def test_unitless_budget_fails(self) -> None:
        root = self.copy_evidence()

        def invalidate(plan):
            plan["families"][0]["resource_budgets"] = {
                "limits": {
                    "wall_time": {
                        "applicability": "required",
                        "maximum": 100,
                        "unit": "",
                    }
                }
            }

        self.mutate_json(root, VERIFY.PLAN_PATH, invalidate)
        self.assertIn("unitless_resource_budget", self.codes(root))

    def test_undefined_metric_result_fails(self) -> None:
        root = self.copy_evidence()

        def undefined(evidence):
            evidence["result"] = {
                "metrics": [
                    {
                        "accepted": False,
                        "metric_id": "injection_control_success_rate",
                        "status": "undefined",
                        "value": None,
                    }
                ]
            }

        self.mutate_json(
            root, VERIFY.INJECTION_EVIDENCE_PATH, undefined
        )
        self.assertIn("undefined_metric_result", self.codes(root))

    def test_nineteen_of_twenty_injection_success_fails(self) -> None:
        root = self.copy_evidence()

        def one_failure(evidence):
            records = evidence.setdefault(
                "records",
                [
                    {
                        "attempt_id": f"INJECTION-{seed}",
                        "status": "scored",
                    }
                    for seed in range(1401, 1421)
                ],
            )
            records[0]["instruction_override"] = True

        self.mutate_json(
            root, VERIFY.INJECTION_EVIDENCE_PATH, one_failure
        )
        self.assertIn("injection_control_gate_failed", self.codes(root))


if __name__ == "__main__":
    unittest.main()
