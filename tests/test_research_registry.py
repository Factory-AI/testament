from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_research", ROOT / "scripts" / "verify_research.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ResearchRegistryTest(unittest.TestCase):
    def copy_repository(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.PUBLIC_FILES:
            source = ROOT / relative
            if source.is_file():
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, root / relative)
        manifest = json.loads(
            (ROOT / "policy/research-manifest.json").read_text(encoding="utf-8")
        )
        for record in manifest["deliverables"]:
            artifact = ROOT / record["artifact"]["path"]
            if artifact.is_file():
                target = root / record["artifact"]["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(artifact, target)
            for evidence in record["evidence"]:
                if evidence["kind"] != "repository":
                    continue
                evidence_path = evidence["locator"].split("#", 1)[0]
                source = ROOT / evidence_path
                if source.is_file():
                    target = root / evidence_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def mutate_manifest(self, root: Path, change) -> None:
        path = root / "policy/research-manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        change(manifest)
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_repository_registry_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_missing_deliverable_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_manifest(root, lambda value: value["deliverables"].pop())
        self.assertIn("missing_deliverable", self.codes(root))

    def test_duplicate_deliverable_fails(self) -> None:
        root = self.copy_repository()

        def duplicate(value) -> None:
            value["deliverables"].append(value["deliverables"][0])

        self.mutate_manifest(root, duplicate)
        self.assertIn("duplicate_deliverable_id", self.codes(root))

    def test_invalid_state_fails(self) -> None:
        root = self.copy_repository()
        self.mutate_manifest(
            root, lambda value: value["deliverables"][0].update(state="done")
        )
        self.assertIn("invalid_deliverable_state", self.codes(root))

    def test_manifest_schema_rejects_unknown_field(self) -> None:
        root = self.copy_repository()
        self.mutate_manifest(
            root, lambda value: value["deliverables"][0].update(undeclared=True)
        )
        self.assertIn("schema_validation_failed", self.codes(root))

    def test_naming_schema_rejects_missing_required_field(self) -> None:
        root = self.copy_repository()
        path = root / "policy/naming-clearance.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        del record["searches"][0]["observation"]
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIn("schema_validation_failed", self.codes(root))

    def test_orphaned_research_file_fails(self) -> None:
        root = self.copy_repository()
        orphan = root / "docs/research/studies/STUDY-ORPHAN-001.md"
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_text("# Orphan\n", encoding="utf-8")
        self.assertIn("orphaned_research_artifact", self.codes(root))

    def test_private_only_evidence_fails(self) -> None:
        root = self.copy_repository()

        def privatize(value) -> None:
            value["deliverables"][0]["evidence"] = [
                {
                    "id": "EVID-PRIVATE",
                    "kind": "repository",
                    "visibility": "private",
                    "locator": "private/notes.md",
                    "claim_supported": "An inaccessible claim.",
                }
            ]

        self.mutate_manifest(root, privatize)
        self.assertIn("private_only_evidence", self.codes(root))

    def test_accepted_item_requires_completed_review(self) -> None:
        root = self.copy_repository()

        def remove_review(value) -> None:
            accepted = next(
                record for record in value["deliverables"] if record["state"] == "accepted"
            )
            accepted["review"]["status"] = "pending"

        self.mutate_manifest(root, remove_review)
        self.assertIn("accepted_without_review", self.codes(root))

    def test_superseded_item_requires_reciprocal_lineage(self) -> None:
        root = self.copy_repository()

        def break_lineage(value) -> None:
            value["deliverables"][0]["state"] = "superseded"
            value["deliverables"][0]["lineage"]["superseded_by"] = None

        self.mutate_manifest(root, break_lineage)
        self.assertIn("missing_supersession_lineage", self.codes(root))

    def test_incompatible_deliverables_cannot_share_artifact(self) -> None:
        root = self.copy_repository()

        def share_path(value) -> None:
            value["deliverables"][1]["artifact"]["path"] = value["deliverables"][0][
                "artifact"
            ]["path"]

        self.mutate_manifest(root, share_path)
        self.assertIn("shared_research_artifact", self.codes(root))

    def test_accepted_artifact_must_exist(self) -> None:
        root = self.copy_repository()
        manifest = json.loads(
            (root / "policy/research-manifest.json").read_text(encoding="utf-8")
        )
        accepted = next(
            record for record in manifest["deliverables"] if record["state"] == "accepted"
        )
        (root / accepted["artifact"]["path"]).unlink()
        self.assertIn("missing_research_artifact", self.codes(root))

    def test_naming_record_requires_every_search_class(self) -> None:
        root = self.copy_repository()
        path = root / "policy/naming-clearance.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["searches"] = [
            search for search in record["searches"] if search["class"] != "trademark"
        ]
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIn("missing_naming_search_class", self.codes(root))

    def test_naming_record_requires_attribution_and_dated_review(self) -> None:
        root = self.copy_repository()
        path = root / "policy/naming-clearance.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["searches"][0]["publisher"] = ""
        record["review"]["reviewed_at"] = None
        path.write_text(json.dumps(record), encoding="utf-8")
        codes = self.codes(root)
        self.assertIn("incomplete_naming_source", codes)
        self.assertIn("incomplete_naming_review", codes)

    def test_unresolved_search_forbids_unconditional_approval(self) -> None:
        root = self.copy_repository()
        path = root / "policy/naming-clearance.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        record["approval"]["status"] = "approved"
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertIn("unsupported_naming_approval", self.codes(root))


if __name__ == "__main__":
    unittest.main()
