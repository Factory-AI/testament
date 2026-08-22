from __future__ import annotations

from collections import Counter
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


GENERATE = load_script("generate_analyzer_evaluation")
VERIFY = load_script("verify_analyzer_evaluation")


class AnalyzerEvaluationFixtureTest(unittest.TestCase):
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

    def test_repository_evidence_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_generation_is_byte_identical(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        corpus_target = root / GENERATE.CORPUS_MANIFEST_PATH
        corpus_target.parent.mkdir(parents=True)
        shutil.copy2(ROOT / GENERATE.CORPUS_MANIFEST_PATH, corpus_target)
        analyzer_plan_target = root / GENERATE.ANALYZER_PLAN_PATH
        analyzer_plan_target.parent.mkdir(parents=True)
        shutil.copy2(ROOT / GENERATE.ANALYZER_PLAN_PATH, analyzer_plan_target)
        generated = GENERATE.expected_files(root)
        GENERATE.write(root, generated)
        for relative in generated:
            self.assertEqual(
                (ROOT / relative).read_bytes(),
                (root / relative).read_bytes(),
                relative,
            )

    def test_injection_manifest_has_exact_seed_and_class_coverage(self) -> None:
        manifest = json.loads(
            (ROOT / GENERATE.INJECTION_MANIFEST_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual(list(range(1401, 1421)), [row["seed"] for row in manifest["cases"]])
        self.assertEqual(
            {injection_class: 2 for injection_class in GENERATE.INJECTION_CLASSES},
            Counter(row["class"] for row in manifest["cases"]),
        )
        self.assertTrue(all(row["byte_count"] > 0 for row in manifest["cases"]))
        self.assertTrue(all(len(row["sha256"]) == 64 for row in manifest["cases"]))

    def test_duplicate_case_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.INJECTION_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["cases"].append(manifest["cases"][0])
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("duplicate_injection_case", self.codes(root))

    def test_missing_case_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.INJECTION_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["cases"].pop()
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("missing_injection_case", self.codes(root))

    def test_fixture_digest_drift_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.injection_path(1401)
        path.write_bytes(path.read_bytes() + b" ")
        self.assertIn("injection_digest_drift", self.codes(root))

    def test_aggregate_digest_drift_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.INJECTION_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["aggregate_dataset_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("aggregate_injection_digest_drift", self.codes(root))

    def test_unknown_fixture_file_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.INJECTION_FIXTURE_ROOT / "unknown.json"
        path.write_text("{}\n", encoding="utf-8")
        self.assertIn("unknown_injection_fixture", self.codes(root))

    def test_unknown_source_fixture_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.INJECTION_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["cases"][0]["source_fixture"] = "FIX-UNKNOWN-001"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("unknown_source_fixture", self.codes(root))

    def test_split_duplicate_case_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["cases"].append(manifest["cases"][0])
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("duplicate_split_case", self.codes(root))

    def test_group_leakage_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        leaked = dict(manifest["groups"][0])
        leaked["partition"] = (
            "holdout" if leaked["partition"] != "holdout" else "development"
        )
        manifest["groups"].append(leaked)
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("group_leakage", self.codes(root))

    def test_empty_required_partition_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        calibration_groups = {
            row["group_id"]
            for row in manifest["groups"]
            if row["partition"] == "calibration"
        }
        for case in manifest["cases"]:
            if case["group_id"] in calibration_groups:
                case["family_applicability"] = []
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("empty_required_partition", self.codes(root))

    def test_injection_leakage_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        injection_group = next(
            case["group_id"]
            for case in manifest["cases"]
            if case["case_kind"] == "injection"
        )
        next(
            group
            for group in manifest["groups"]
            if group["group_id"] == injection_group
        )["partition"] = "development"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("injection_partition_leakage", self.codes(root))

    def test_algorithm_version_drift_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["algorithm"]["hash"] = "SHA-512"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("split_algorithm_drift", self.codes(root))

    def test_analyzer_plan_binding_drift_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.ANALYZER_PLAN_PATH
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["status"] = "superseded"
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("split_binding_drift", self.codes(root))

    def test_authorized_twins_share_group_and_partition(self) -> None:
        manifest = json.loads(
            (ROOT / GENERATE.SPLIT_MANIFEST_PATH).read_text(encoding="utf-8")
        )
        cases = {
            row["source_fixture"]: row
            for row in manifest["cases"]
            if row["source_fixture"] in GENERATE.AUTHORIZED_TWIN_FIXTURES
        }
        self.assertEqual(1, len({row["group_id"] for row in cases.values()}))

    def test_authorized_twin_group_leakage_fails(self) -> None:
        root = self.copy_evidence()
        path = root / GENERATE.SPLIT_MANIFEST_PATH
        manifest = json.loads(path.read_text(encoding="utf-8"))
        twin = next(
            case
            for case in manifest["cases"]
            if case["source_fixture"] == "FIX-AUTHORIZED-TWIN-001"
        )
        twin["group_id"] = next(
            group["group_id"]
            for group in manifest["groups"]
            if group["partition"] == "holdout"
        )
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("authorized_twin_group_leakage", self.codes(root))
