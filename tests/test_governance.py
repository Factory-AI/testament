from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_governance", ROOT / "scripts" / "verify_governance.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class GovernanceLifecycleTest(unittest.TestCase):
    def copy_repository(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        required = set(VERIFY.PUBLIC_DOCUMENTS)
        for kind in ("rfcs", "adrs"):
            index = json.loads((ROOT / f"docs/{kind}/index.json").read_text(encoding="utf-8"))
            required.update(record["path"] for record in index["records"])
        for name in sorted(required):
            source = ROOT / name
            if source.exists():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, root / name)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def test_accepted_record_byte_mutation_fails(self) -> None:
        root = self.copy_repository()
        index = json.loads((root / "docs/rfcs/index.json").read_text(encoding="utf-8"))
        accepted = next(record for record in index["records"] if record["status"] == "accepted")
        with (root / accepted["path"]).open("a", encoding="utf-8") as handle:
            handle.write("\nUndocumented mutation.\n")
        self.assertIn("immutable_record_changed", self.codes(root))

    def test_invalid_status_fails(self) -> None:
        root = self.copy_repository()
        path = root / "docs/adrs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["records"][0]["status"] = "done"
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("invalid_record_status", self.codes(root))

    def test_broken_supersession_fails(self) -> None:
        root = self.copy_repository()
        path = root / "docs/rfcs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        superseded = next(record for record in index["records"] if record["status"] == "superseded")
        superseded["superseded_by"] = "RFC-9999"
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("broken_supersession", self.codes(root))

    def test_orphaned_record_fails(self) -> None:
        root = self.copy_repository()
        (root / "docs/rfcs/9999-orphan.md").write_text("# Orphan\n", encoding="utf-8")
        self.assertIn("orphaned_record", self.codes(root))

    def test_private_reporting_must_be_enabled(self) -> None:
        root = self.copy_repository()
        path = root / "policy/governance-lifecycle.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["private_vulnerability_reporting"]["enabled"] = False
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("private_reporting_evidence_invalid", self.codes(root))

    def test_reverse_supersession_must_resolve(self) -> None:
        root = self.copy_repository()
        path = root / "docs/adrs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        accepted = next(record for record in index["records"] if record["status"] == "accepted")
        accepted["supersedes"] = "ADR-9999"
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("broken_supersession", self.codes(root))

    def test_non_string_id_reports_failure(self) -> None:
        root = self.copy_repository()
        path = root / "docs/rfcs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["records"][0]["id"] = []
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("invalid_record_id", self.codes(root))

    def test_record_path_cannot_escape_directory(self) -> None:
        root = self.copy_repository()
        path = root / "docs/rfcs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["records"][0]["path"] = "docs/rfcs/../../../outside.md"
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("invalid_record_path", self.codes(root))

    def test_expired_bootstrap_exception_fails(self) -> None:
        root = self.copy_repository()
        path = root / "docs/rfcs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["records"][0]["bootstrap_expiry"] = "2020-01-01"
        path.write_text(json.dumps(index), encoding="utf-8")
        self.assertIn("invalid_bootstrap_exception", self.codes(root))

    def test_mutable_lineage_must_match_immutable_header(self) -> None:
        root = self.copy_repository()
        path = root / "docs/adrs/index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        accepted = next(record for record in index["records"] if record["status"] == "accepted")
        accepted["record_supersedes"] = None
        path.write_text(json.dumps(index), encoding="utf-8")
        codes = self.codes(root)
        self.assertIn("mutable_lineage_mismatch", codes)
        self.assertIn("record_index_drift", codes)


if __name__ == "__main__":
    unittest.main()
