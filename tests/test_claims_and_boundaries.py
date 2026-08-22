from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_claims", ROOT / "scripts" / "verify_claims.py"
)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ClaimsAndBoundariesTest(unittest.TestCase):
    def copy_contracts(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.PUBLIC_FILES:
            source = ROOT / relative
            if source.is_file():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    @staticmethod
    def load(root: Path, relative: str) -> dict:
        return json.loads((root / relative).read_text(encoding="utf-8"))

    @staticmethod
    def write(root: Path, relative: str, value: dict) -> None:
        (root / relative).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_repository_claims_and_boundaries_pass(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_every_architecture_claim_has_reverse_coverage(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        del ledger["claims"][0]
        self.write(root, "policy/claims-ledger.json", ledger)
        self.assertIn("missing_architecture_claim", self.codes(root))

    def test_claim_requires_observation_inference_and_limits(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        claim = ledger["claims"][0]
        claim["observation"] = ""
        claim["inference"] = ""
        claim["uncertainty"] = ""
        claim["limitations"] = []
        self.write(root, "policy/claims-ledger.json", ledger)
        codes = self.codes(root)
        self.assertIn("schema_validation_failed", codes)
        self.assertIn("incomplete_claim_reasoning", codes)

    def test_claim_requires_contradiction_review_and_supersession(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        claim = ledger["claims"][0]
        claim["contradictory_evidence"] = []
        claim["review"]["status"] = "completed"
        claim["review"]["reviewed_at"] = None
        claim["supersession"].pop("superseded_by")
        self.write(root, "policy/claims-ledger.json", ledger)
        codes = self.codes(root)
        self.assertIn("schema_validation_failed", codes)
        self.assertIn("incomplete_claim_contradiction", codes)
        self.assertIn("incomplete_claim_review", codes)
        self.assertIn("incomplete_claim_supersession", codes)

    def test_inaccessible_evidence_cannot_support_pass(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        claim = ledger["claims"][0]
        claim["status"] = "supported"
        evidence = next(
            item for item in ledger["evidence"] if item["id"] == claim["evidence_ids"][0]
        )
        evidence["path"] = "docs/missing-evidence.json"
        self.write(root, "policy/claims-ledger.json", ledger)
        self.assertIn("unsupported_claim_status", self.codes(root))

    def test_claim_text_must_match_its_source_pointer(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        ledger["claims"][0]["claim"] = "A broader unsupported claim."
        self.write(root, "policy/claims-ledger.json", ledger)
        self.assertIn("claim_source_text_drift", self.codes(root))

    def test_evidence_requires_date_version_and_exact_supported_claim(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        evidence = ledger["evidence"][0]
        evidence["publisher"] = ""
        evidence["publication_date"] = None
        evidence["version"] = ""
        evidence["claim_supported"] = ""
        self.write(root, "policy/claims-ledger.json", ledger)
        codes = self.codes(root)
        self.assertIn("schema_validation_failed", codes)
        self.assertIn("incomplete_claim_evidence", codes)

    def test_only_inventoried_normative_source_can_feed_conformance(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["conformance_inputs"][0]["source_id"] = "NORM-UNKNOWN"
        self.write(root, "policy/normative-sources.json", boundaries)
        self.assertIn("unknown_conformance_source", self.codes(root))

    def test_every_normative_source_has_one_conformance_input(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["conformance_inputs"].pop()
        self.write(root, "policy/normative-sources.json", boundaries)
        self.assertIn("incomplete_conformance_source_coverage", self.codes(root))

    def test_informative_path_cannot_feed_conformance(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["conformance_inputs"][0]["path"] = (
            "docs/research/studies/trace-landscape.md"
        )
        self.write(root, "policy/normative-sources.json", boundaries)
        self.assertIn("informative_conformance_input", self.codes(root))

    def test_informative_rfc_section_cannot_feed_conformance(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["conformance_inputs"][0]["section"] = "Informative rationale"
        self.write(root, "policy/normative-sources.json", boundaries)
        self.assertIn("informative_conformance_input", self.codes(root))

    def test_unpromoted_fixture_cannot_feed_conformance(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["conformance_inputs"].append(
            {
                "id": "CONF-FIXTURE-UNPROMOTED",
                "source_id": "NORM-RFC-0014",
                "path": "docs/research/corpus/manifest.json",
                "section": "$.fixtures[0]",
                "version": "1.0.0",
                "rendered_status": "Informative research fixture",
            }
        )
        self.write(root, "policy/normative-sources.json", boundaries)
        self.assertIn("unpromoted_conformance_fixture", self.codes(root))

    def test_rfc_status_and_digest_must_match_normative_inventory(self) -> None:
        root = self.copy_contracts()
        boundaries = self.load(root, "policy/normative-sources.json")
        boundaries["sources"][0]["status"] = "accepted"
        boundaries["sources"][0]["sha256"] = "0" * 64
        self.write(root, "policy/normative-sources.json", boundaries)
        codes = self.codes(root)
        self.assertIn("normative_source_status_drift", codes)
        self.assertIn("normative_source_digest_drift", codes)

    def test_rendered_status_is_explicit_and_linked(self) -> None:
        root = self.copy_contracts()
        text = (root / "docs/standards-status.md").read_text(encoding="utf-8")
        (root / "docs/standards-status.md").write_text(
            text.replace("Normative draft", "Document"),
            encoding="utf-8",
        )
        self.assertIn("incomplete_rendered_status", self.codes(root))

    def test_schema_rejects_unknown_claim_field(self) -> None:
        root = self.copy_contracts()
        ledger = self.load(root, "policy/claims-ledger.json")
        ledger["claims"][0]["undeclared"] = True
        self.write(root, "policy/claims-ledger.json", ledger)
        self.assertIn("schema_validation_failed", self.codes(root))


if __name__ == "__main__":
    unittest.main()
