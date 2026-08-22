from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_foundation", ROOT / "scripts" / "verify_foundation.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class FoundationPolicyTest(unittest.TestCase):
    def make_valid_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "policy").mkdir()
        for name in ("artifact-licensing.json", "claims.json"):
            (root / "policy" / name).write_text(
                (ROOT / "policy" / name).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        (root / "docs").mkdir()
        claims = json.loads((root / "policy" / "claims.json").read_text(encoding="utf-8"))
        limitations = "\n".join(item["text"] for item in claims["required_limitations"])
        for name in ("README.md", "CHARTER.md", "TERMINOLOGY.md"):
            (root / name).write_text("# Test\n", encoding="utf-8")
        (root / "docs" / "claims-policy.md").write_text(limitations, encoding="utf-8")
        (root / "docs" / "licensing.md").write_text("# Licensing\n", encoding="utf-8")
        (root / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
        (root / "NOTICE").write_text("Testament\n", encoding="utf-8")
        return root

    def test_complete_policy_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(self.make_valid_root()))

    def test_missing_artifact_class_fails(self) -> None:
        root = self.make_valid_root()
        path = root / "policy" / "artifact-licensing.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["artifact_classes"] = [
            item for item in inventory["artifact_classes"] if item["id"] != "fixtures"
        ]
        path.write_text(json.dumps(inventory), encoding="utf-8")
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("missing_artifact_class", codes)

    def test_forbidden_core_dependency_fails(self) -> None:
        root = self.make_valid_root()
        path = root / "policy" / "artifact-licensing.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["dependencies"] = [
            {
                "id": "example.test/forbidden",
                "version": "v1.0.0",
                "license": "AGPL-3.0",
                "usage": "core",
                "manifest": "go.mod",
            }
        ]
        path.write_text(json.dumps(inventory), encoding="utf-8")
        (root / "go.mod").write_text(
            "module example.test/testament\n",
            encoding="utf-8",
        )
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("forbidden_core_dependency", codes)

    def test_forbidden_claim_fails(self) -> None:
        root = self.make_valid_root()
        with (root / "README.md").open("a", encoding="utf-8") as handle:
            handle.write("Testament guarantees perfect safety.\n")
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("forbidden_claim", codes)

    def test_missing_limitation_fails(self) -> None:
        root = self.make_valid_root()
        path = root / "docs" / "claims-policy.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "Testament does not automatically enforce decisions.", ""
            ),
            encoding="utf-8",
        )
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("missing_required_limitation", codes)

    def test_claim_policy_cannot_disable_checks(self) -> None:
        root = self.make_valid_root()
        path = root / "policy" / "claims.json"
        claims = json.loads(path.read_text(encoding="utf-8"))
        claims["required_limitations"] = []
        claims["forbidden_claims"] = []
        path.write_text(json.dumps(claims), encoding="utf-8")
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("required_limitations_changed", codes)
        self.assertIn("forbidden_claims_changed", codes)

    def test_truncated_license_fails(self) -> None:
        root = self.make_valid_root()
        (root / "LICENSE").write_text(
            "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n",
            encoding="utf-8",
        )
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("invalid_project_license", codes)

    def test_malformed_policy_shape_reports_failure(self) -> None:
        root = self.make_valid_root()
        (root / "policy" / "claims.json").write_text("[]", encoding="utf-8")
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertIn("invalid_policy_shape", codes)


if __name__ == "__main__":
    unittest.main()
