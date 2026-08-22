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

    def test_each_supported_manifest_dependency_requires_inventory_entry(self) -> None:
        manifests = {
            "Cargo.toml": '[dependencies]\nexample-cargo = "1.2.3"\n',
            "go.mod": (
                "module example.test/testament\n\n"
                "go 1.26\n\n"
                "require example.test/go-dependency v1.2.3\n"
            ),
            "package.json": json.dumps(
                {"dependencies": {"example-npm": "1.2.3"}}
            ),
            "requirements.txt": "example-python==1.2.3\n",
        }
        expected_ids = {
            "Cargo.toml": "example-cargo",
            "go.mod": "example.test/go-dependency",
            "package.json": "example-npm",
            "requirements.txt": "example-python",
        }

        for manifest, content in manifests.items():
            with self.subTest(manifest=manifest):
                root = self.make_valid_root()
                (root / manifest).write_text(content, encoding="utf-8")
                problems = VERIFY.validate(root)
                missing = [
                    problem
                    for problem in problems
                    if problem["code"] == "missing_dependency_inventory_entry"
                ]
                self.assertEqual(1, len(missing))
                self.assertEqual(manifest, missing[0]["path"])
                self.assertIn(expected_ids[manifest], missing[0]["message"])
                self.assertIn(
                    "policy/artifact-licensing.json",
                    missing[0]["remediation_command"],
                )

    def test_empty_supported_manifest_needs_no_inventory_entry(self) -> None:
        root = self.make_valid_root()
        (root / "package.json").write_text("{}\n", encoding="utf-8")
        codes = {problem["code"] for problem in VERIFY.validate(root)}
        self.assertNotIn("unaccounted_dependency_manifest", codes)
        self.assertNotIn("missing_dependency_inventory_entry", codes)

    def test_inventory_omission_mutation_cannot_pass(self) -> None:
        root = self.make_valid_root()
        (root / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {
                        "example-first": "1.0.0",
                        "example-second": "2.0.0",
                    }
                }
            ),
            encoding="utf-8",
        )
        path = root / "policy" / "artifact-licensing.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["dependencies"] = [
            {
                "id": "example-first",
                "version": "1.0.0",
                "license": "MIT",
                "usage": "test",
                "manifest": "package.json",
            }
        ]
        path.write_text(json.dumps(inventory), encoding="utf-8")

        missing = [
            problem
            for problem in VERIFY.validate(root)
            if problem["code"] == "missing_dependency_inventory_entry"
        ]
        self.assertEqual(
            ["Dependency example-second@2.0.0 declared in package.json is missing "
             "from the licensing inventory"],
            [problem["message"] for problem in missing],
        )

    def test_all_package_dependency_groups_are_reconciled(self) -> None:
        root = self.make_valid_root()
        (root / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"example-runtime": "1.0.0"},
                    "devDependencies": {"example-dev": "2.0.0"},
                    "optionalDependencies": {"example-optional": "3.0.0"},
                    "peerDependencies": {"example-peer": "4.0.0"},
                }
            ),
            encoding="utf-8",
        )
        path = root / "policy" / "artifact-licensing.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["dependencies"] = [
            {
                "id": dependency_id,
                "version": version,
                "license": "MIT",
                "usage": "test",
                "manifest": "package.json",
            }
            for dependency_id, version in (
                ("example-runtime", "1.0.0"),
                ("example-dev", "2.0.0"),
                ("example-optional", "3.0.0"),
            )
        ]
        path.write_text(json.dumps(inventory), encoding="utf-8")

        missing = [
            problem["message"]
            for problem in VERIFY.validate(root)
            if problem["code"] == "missing_dependency_inventory_entry"
        ]
        self.assertEqual(
            [
                "Dependency example-peer@4.0.0 declared in package.json is missing "
                "from the licensing inventory"
            ],
            missing,
        )

    def test_supported_manifest_forms_reconcile_exact_inventory(self) -> None:
        root = self.make_valid_root()
        (root / "Cargo.toml").write_text(
            '[workspace.dependencies]\n'
            'serde-alias = { package = "serde", version = "1.0.219" }\n'
            '\n[dependencies]\n'
            'serde-alias = { workspace = true }\n'
            '\n[target.\'cfg(unix)\'.dev-dependencies]\n'
            'example-target = { git = "https://example.test/repository", rev = "abc123" }\n',
            encoding="utf-8",
        )
        (root / "go.mod").write_text(
            "module example.test/testament\n\n"
            "go 1.26\n\n"
            "require (\n"
            "\texample.test/first v1.2.3 // indirect\n"
            "\texample.test/second v2.3.4\n"
            ")\n",
            encoding="utf-8",
        )
        (root / "requirements.txt").write_text(
            "example-python[security]>=1.2, <2; python_version >= '3.14'\n"
            "example-source @ https://example.test/archive.whl\n",
            encoding="utf-8",
        )
        records = VERIFY.declared_dependencies(root, [])
        expected = {
            ("Cargo.toml", "serde", "1.0.219"),
            (
                "Cargo.toml",
                "example-target",
                "git:https://example.test/repository#abc123",
            ),
            ("go.mod", "example.test/first", "v1.2.3"),
            ("go.mod", "example.test/second", "v2.3.4"),
            ("requirements.txt", "example-python", ">=1.2,<2"),
            (
                "requirements.txt",
                "example-source",
                "@ https://example.test/archive.whl",
            ),
        }
        self.assertEqual(expected, set(records))

        path = root / "policy" / "artifact-licensing.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["dependencies"] = [
            {
                "id": dependency_id,
                "version": version,
                "license": "MIT",
                "usage": "test",
                "manifest": manifest,
            }
            for manifest, dependency_id, version in sorted(expected)
        ]
        path.write_text(json.dumps(inventory), encoding="utf-8")
        self.assertNotIn(
            "missing_dependency_inventory_entry",
            {problem["code"] for problem in VERIFY.validate(root)},
        )

    def test_malformed_requirement_fails_instead_of_skipping_reconciliation(self) -> None:
        root = self.make_valid_root()
        (root / "requirements.txt").write_text(
            "example-python not-a-version\n",
            encoding="utf-8",
        )
        problems = VERIFY.validate(root)
        self.assertTrue(
            any(
                problem["code"] == "invalid_dependency_manifest"
                and problem["path"] == "requirements.txt"
                for problem in problems
            )
        )

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
