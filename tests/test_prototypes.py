from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_prototypes", ROOT / "scripts" / "verify_prototypes.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class PrototypeEvidenceTest(unittest.TestCase):
    def copy_evidence(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.EVIDENCE_FILES:
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def test_repository_evidence_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_every_prototype_has_precommit_and_raw_result(self) -> None:
        plan = json.loads(
            (ROOT / "docs/research/benchmarks/precommit.json").read_text(
                encoding="utf-8"
            )
        )
        expected = set(VERIFY.PROTOTYPES)
        self.assertEqual(expected, {case["id"] for case in plan["cases"]})
        self.assertEqual(
            expected,
            {
                json.loads((ROOT / path).read_text(encoding="utf-8"))[
                    "prototype_id"
                ]
                for path in VERIFY.RESULT_FILES
            },
        )

    def test_post_result_budget_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/precommit.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["cases"][0]["budgets"]["max_elapsed_ms"] += 1
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("result_plan_digest_mismatch", self.codes(root))

    def test_missing_raw_sample_fails(self) -> None:
        root = self.copy_evidence()
        path = root / VERIFY.RESULT_FILES[0]
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"].pop()
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("wrong_sample_count", self.codes(root))

    def test_analyzer_matrix_requires_every_family_and_dimension(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"] = [
            row for row in plan["families"] if row["family"] != "external-llm"
        ]
        plan["families"][0]["prompt_injection"].pop()
        path.write_text(json.dumps(plan), encoding="utf-8")
        codes = self.codes(root)
        self.assertIn("missing_analyzer_family", codes)
        self.assertIn("incomplete_analyzer_dimension", codes)

    def test_postgres_result_binds_declared_lifecycle(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/postgres-storage.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["environment"]["postgres"]["port"] = 5432
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_postgres_environment", self.codes(root))


if __name__ == "__main__":
    unittest.main()
