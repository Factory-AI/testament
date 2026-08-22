from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_corpus", ROOT / "scripts" / "verify_corpus.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)
GENERATOR = VERIFY.GENERATOR


class SyntheticCorpusTest(unittest.TestCase):
    def copy_corpus(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.CORPUS_FILES:
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def load_manifest(self, root: Path) -> dict:
        return json.loads(
            (root / VERIFY.MANIFEST_PATH).read_text(encoding="utf-8")
        )

    def write_manifest(self, root: Path, manifest: dict) -> None:
        (root / VERIFY.MANIFEST_PATH).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    def test_repository_corpus_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_required_fixture_classes_are_exactly_covered(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        manifest["fixtures"] = [
            fixture
            for fixture in manifest["fixtures"]
            if "missing-lineage" not in fixture["classes"]
        ]
        self.write_manifest(root, manifest)
        self.assertIn("missing_fixture_class", self.codes(root))

    def test_fixture_byte_mutation_fails_digest_and_generation(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        fixture = manifest["fixtures"][0]
        path = root / fixture["path"]
        path.write_bytes(path.read_bytes() + b"\n")
        codes = self.codes(root)
        self.assertIn("fixture_digest_mismatch", codes)
        self.assertIn("fixture_generation_mismatch", codes)

    def test_digest_only_update_cannot_hide_byte_mutation(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        fixture = manifest["fixtures"][0]
        path = root / fixture["path"]
        path.write_bytes(path.read_bytes() + b"\n")
        fixture["byte_count"] = path.stat().st_size
        fixture["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_manifest(root, manifest)
        self.assertIn("fixture_generation_mismatch", self.codes(root))

    def test_changed_bytes_require_version_provenance_and_expectation_updates(self) -> None:
        previous = self.load_manifest(ROOT)
        current = json.loads(json.dumps(previous))
        current["fixtures"][0]["sha256"] = "0" * 64
        failures = VERIFY.synchronized_change_problems(previous, current)
        self.assertTrue(any("version" in failure for failure in failures))
        self.assertTrue(any("provenance" in failure for failure in failures))
        self.assertTrue(any("expectations" in failure for failure in failures))

    def test_synchronized_fixture_revision_is_accepted(self) -> None:
        previous = self.load_manifest(ROOT)
        current = json.loads(json.dumps(previous))
        current["version"] = "1.1.0"
        fixture = current["fixtures"][0]
        fixture["sha256"] = "0" * 64
        fixture["version"] = "1.1.0"
        fixture["provenance"]["recipe"] = "openai_stream_tool_v2"
        fixture["expectations"]["semantic_assertions"].append(
            "Revision-specific expectation."
        )
        self.assertEqual(
            [], VERIFY.synchronized_change_problems(previous, current)
        )

    def test_fixture_revision_also_requires_corpus_version_update(self) -> None:
        previous = self.load_manifest(ROOT)
        current = json.loads(json.dumps(previous))
        fixture = current["fixtures"][0]
        fixture["sha256"] = "0" * 64
        fixture["version"] = "1.1.0"
        fixture["provenance"]["recipe"] = "openai_stream_tool_v2"
        fixture["expectations"]["semantic_assertions"].append(
            "Revision-specific expectation."
        )
        failures = VERIFY.synchronized_change_problems(previous, current)
        self.assertTrue(
            any("corpus version did not advance" in failure for failure in failures)
        )

    def test_research_registry_version_must_match_corpus(self) -> None:
        root = self.copy_corpus()
        path = root / "policy/research-manifest.json"
        registry = json.loads(path.read_text(encoding="utf-8"))
        corpus = next(
            record
            for record in registry["deliverables"]
            if record["id"] == "RES-CORPUS-SYNTHETIC-TRACE-001"
        )
        corpus["version"] = "0.9.0"
        path.write_text(json.dumps(registry), encoding="utf-8")
        self.assertIn("corpus_registry_drift", self.codes(root))

    def test_nested_manifest_contract_rejects_unknown_fields(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        manifest["fixtures"][0]["provenance"]["undeclared"] = True
        self.write_manifest(root, manifest)
        self.assertIn("corpus_schema_validation_failed", self.codes(root))

    def test_every_fixture_recipe_consumes_its_seed(self) -> None:
        for definition in VERIFY.GENERATOR.FIXTURES:
            self.assertNotEqual(
                definition["builder"]("seed-a"),
                definition["builder"]("seed-b"),
                definition["id"],
            )

    def test_fixture_requires_provenance_expectation_version_and_license(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        fixture = manifest["fixtures"][0]
        fixture["version"] = ""
        fixture["provenance"] = {}
        fixture["expectations"] = {}
        fixture["redistribution_license"]["spdx"] = "LicenseRef-Unknown"
        self.write_manifest(root, manifest)
        codes = self.codes(root)
        self.assertIn("incomplete_fixture_metadata", codes)
        self.assertIn("unapproved_fixture_license", codes)

    def test_secret_privacy_and_unsafe_content_scans_fail_closed(self) -> None:
        root = self.copy_corpus()
        manifest = self.load_manifest(root)
        fixture = manifest["fixtures"][0]
        path = root / fixture["path"]
        path.write_bytes(
            path.read_bytes()
            + b"\nAKIAIOSFODNN7EXAMPLE person@example.test password=hunter2"
        )
        fixture["byte_count"] = path.stat().st_size
        fixture["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write_manifest(root, manifest)
        problems = VERIFY.validate(root)
        codes = {problem["code"] for problem in problems}
        self.assertIn("possible_secret_in_fixture", codes)
        self.assertIn("possible_pii_in_fixture", codes)
        secret_messages = {
            problem["message"]
            for problem in problems
            if problem["code"] == "possible_secret_in_fixture"
        }
        self.assertEqual(
            {"Sensitive pattern detected; fixture bytes and category withheld"},
            secret_messages,
        )

    def test_giant_json_and_jsonl_are_both_present(self) -> None:
        manifest = self.load_manifest(ROOT)
        giant_formats = {
            fixture["format"]
            for fixture in manifest["fixtures"]
            if "giant" in fixture["classes"]
        }
        self.assertEqual({"json", "jsonl"}, giant_formats)

    def test_clean_checkout_regenerates_identical_bytes(self) -> None:
        root = self.copy_corpus()
        completed = subprocess.run(
            [
                "python3",
                str(root / "scripts/generate_corpus.py"),
                "--root",
                str(root),
                "--check",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_write_rejects_traversal_outside_repository(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        outside = root.parent / f"{root.name}-escaped"
        self.addCleanup(outside.unlink, missing_ok=True)

        with self.assertRaisesRegex(ValueError, "outside repository"):
            GENERATOR.write(root, {f"../{outside.name}": b"escaped"})

        self.assertFalse(outside.exists())

    def test_write_rejects_symlinked_target(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        outside = root.parent / f"{root.name}-outside"
        outside.write_bytes(b"unchanged")
        self.addCleanup(outside.unlink, missing_ok=True)
        target = root / "fixture.json"
        target.symlink_to(outside)

        with self.assertRaisesRegex(ValueError, "symlink"):
            GENERATOR.write(root, {"fixture.json": b"replacement"})

        self.assertEqual(b"unchanged", outside.read_bytes())

    def test_write_rejects_symlinked_path_ancestor(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside)
        (root / "fixtures").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symlink"):
            GENERATOR.write(root, {"fixtures/nested.json": b"replacement"})

        self.assertFalse((outside / "nested.json").exists())

    def test_write_uses_exclusive_random_temp_names_after_collision(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        collision = root / ".fixture.json.tmp-collision"
        collision.write_bytes(b"do-not-overwrite")

        with mock.patch.object(
            GENERATOR.secrets,
            "token_hex",
            side_effect=["collision", "replacement"],
        ):
            GENERATOR.write(root, {"fixture.json": b"fixture"})

        self.assertEqual(b"do-not-overwrite", collision.read_bytes())
        self.assertEqual(b"fixture", (root / "fixture.json").read_bytes())
        self.assertFalse((root / ".fixture.json.tmp-replacement").exists())

    def test_interrupted_atomic_replace_cleans_temporary_file(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)

        with mock.patch.object(
            GENERATOR.os,
            "replace",
            side_effect=OSError("injected replacement interruption"),
        ):
            with self.assertRaisesRegex(OSError, "injected replacement interruption"):
                GENERATOR.write(root, {"fixture.json": b"fixture"})

        self.assertFalse((root / "fixture.json").exists())
        self.assertEqual([], list(root.glob(".fixture.json.tmp-*")))

    def test_git_attributes_preserve_fixture_bytes(self) -> None:
        root = self.copy_corpus()
        (root / ".gitattributes").write_text("", encoding="utf-8")
        self.assertIn("missing_fixture_git_attributes", self.codes(root))


if __name__ == "__main__":
    unittest.main()
