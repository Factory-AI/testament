from __future__ import annotations

import importlib.util
import copy
import hashlib
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
RUN_SPEC = importlib.util.spec_from_file_location(
    "run_prototypes", ROOT / "scripts" / "run_prototypes.py"
)
assert RUN_SPEC and RUN_SPEC.loader
RUN = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(RUN)


class PrototypeEvidenceTest(unittest.TestCase):
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

    def test_analyzer_evaluation_evidence_passes(self) -> None:
        self.assertEqual(
            [],
            [
                problem
                for problem in VERIFY.validate(ROOT)
                if problem["criterion_id"] == "VAL-READY-015"
            ],
        )

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

    def test_successor_plan_precommits_all_review_remediations(self) -> None:
        plan = json.loads(
            (ROOT / VERIFY.SUCCESSOR_PLAN_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual("2.0.0", plan["version"])
        self.assertEqual(
            VERIFY.CANONICAL_PLAN_COMMIT,
            plan["supersedes"]["commit"],
        )
        self.assertEqual(
            {"F-001", "F-002", "F-003"},
            {row["finding_id"] for row in plan["remediations"]},
        )

    def test_successor_budget_widening_fails(self) -> None:
        root = self.copy_evidence()
        path = root / VERIFY.SUCCESSOR_PLAN_PATH
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["cases"][0]["budgets"]["max_process_rss_bytes"] += 1
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("successor_budget_or_tolerance_drift", self.codes(root))

    def test_successor_missing_resource_source_fails(self) -> None:
        root = self.copy_evidence()
        path = root / VERIFY.SUCCESSOR_PLAN_PATH
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["remediations"][0]["local_samples"]["source"] = ""
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn(
            "incomplete_successor_resource_accounting",
            self.codes(root),
        )

    def test_successor_missing_disconnect_evidence_fails(self) -> None:
        root = self.copy_evidence()
        path = root / VERIFY.SUCCESSOR_PLAN_PATH
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["remediations"][2]["precommit"]["required_evidence"].pop()
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn(
            "incomplete_successor_finding_methods",
            self.codes(root),
        )

    def test_key_rotation_captures_payload_independently(self) -> None:
        observation = RUN.key_rotation(ROOT)
        self.assertTrue(RUN.key_rotation_accepted(observation))
        self.assertTrue(VERIFY.valid_v2_key_rotation_observation(observation))
        self.assertEqual(
            [
                "pre_payload_capture",
                "new_wrapped_dek_persisted",
                "checkpoint_persisted",
                "post_payload_capture",
            ],
            observation["operation_sequence"],
        )
        before = observation["pre_rewrap_payload_capture"]
        after = observation["post_rewrap_payload_capture"]
        self.assertEqual(before["sha256"], after["sha256"])
        self.assertEqual(before["byte_count"], after["byte_count"])
        self.assertNotEqual(before["capture_id"], after["capture_id"])
        self.assertEqual(1, before["read_ordinal"])
        self.assertEqual(2, after["read_ordinal"])

    def test_key_rotation_harness_rejects_changed_payload_byte(self) -> None:
        observation = RUN.key_rotation(ROOT, mutation="payload-byte")
        self.assertNotEqual(
            observation["pre_rewrap_payload_capture"]["sha256"],
            observation["post_rewrap_payload_capture"]["sha256"],
        )
        self.assertFalse(observation["payload_ciphertext_unchanged"])
        self.assertFalse(RUN.key_rotation_accepted(observation))
        self.assertFalse(VERIFY.valid_v2_key_rotation_observation(observation))

    def test_key_rotation_mutations_fail_recomputed_acceptance(self) -> None:
        observation = RUN.key_rotation(ROOT)
        mutations = {
            "missing capture": lambda value: value.pop(
                "post_rewrap_payload_capture"
            ),
            "non-independent capture": lambda value: value[
                "post_rewrap_payload_capture"
            ].update(
                capture_id=value["pre_rewrap_payload_capture"]["capture_id"]
            ),
            "non-independent method": lambda value: value[
                "post_rewrap_payload_capture"
            ].update(method="cached-in-memory-value"),
            "changed digest": lambda value: value[
                "post_rewrap_payload_capture"
            ].update(sha256="0" * 64),
            "changed byte count": lambda value: value[
                "post_rewrap_payload_capture"
            ].update(
                byte_count=value["post_rewrap_payload_capture"]["byte_count"]
                + 1
            ),
            "equal wrapped DEKs": lambda value: value[
                "new_wrapped_dek"
            ].update(sha256=value["old_wrapped_dek"]["sha256"]),
            "wrong generations": lambda value: value.update(generations=[1, 1]),
            "wrong checkpoint": lambda value: value.update(resume_checkpoint=2),
            "inconsistent unchanged assertion": lambda value: value.update(
                payload_ciphertext_unchanged=False
            ),
            "inconsistent rewrap assertion": lambda value: value.update(
                rewrap_changed=False
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(observation)
                mutate(changed)
                self.assertFalse(RUN.key_rotation_accepted(changed))
                self.assertFalse(
                    VERIFY.valid_v2_key_rotation_observation(changed)
                )

    def test_version_one_key_rotation_result_is_immutable(self) -> None:
        path = ROOT / "docs/research/benchmarks/key-rotation.json"
        self.assertEqual(
            VERIFY.V1_KEY_ROTATION_SHA256,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )

    def test_key_rotation_v2_result_recomputes_every_sample(self) -> None:
        plan = json.loads(
            (ROOT / VERIFY.SUCCESSOR_PLAN_PATH).read_text(encoding="utf-8")
        )
        case_plan = next(
            row for row in plan["cases"] if row["id"] == "key-rotation"
        )
        observation = RUN.key_rotation(ROOT)
        observation["worker_completed"] = True
        accounting = {
            "accounting_version": "2.0.0",
            "scope": "worker_descendant_tree",
            "metric": "aggregate_peak_resident_bytes",
            "source": "external_ps_process_table",
            "target": "worker_pid:1",
            "isolation": "fresh_process_group",
            "descendants_included": True,
            "peak_rss_bytes": 1,
            "budget_bytes": case_plan["budgets"]["max_process_rss_bytes"],
            "hard_limit_bytes": case_plan["budgets"]["max_process_rss_bytes"],
            "within_budget": True,
        }
        sample = {
            "elapsed_ms": 1,
            "resource_accounting": accounting,
            "observation": observation,
        }
        result = {
            "schema_version": "1.0.0",
            "feature_id": "key-rotation-independent-ciphertext-evidence",
            "validation_id": "VAL-READY-014",
            "prototype_id": "key-rotation",
            "benchmark_id": "key-rotation-benchmark",
            "version": "2.0.0",
            "plan_commit": VERIFY.SUCCESSOR_PLAN_COMMIT,
            "plan_sha256": VERIFY.digest(plan),
            "environment": {"tested_commit": "1" * 40},
            "inputs": case_plan["inputs"],
            "sample_count": case_plan["sample_count"],
            "budgets": case_plan["budgets"],
            "tolerances": case_plan["tolerances"],
            "comparison_method": case_plan["comparison_method"],
            "acceptance_rule": case_plan["acceptance_rule"],
            "samples": [copy.deepcopy(sample) for _ in range(3)],
            "conclusion": "pass",
            "limitations": case_plan["limitations"],
            "tolerance_history": plan["tolerance_history"],
            "supersedes": {
                "path": "docs/research/benchmarks/key-rotation.json",
                "version": "1.0.0",
                "sha256": VERIFY.V1_KEY_ROTATION_SHA256,
                "status": "superseded-evidence",
                "preserved": True,
            },
        }
        self.assertTrue(VERIFY.valid_v2_key_rotation_result(result, plan))
        mutations = {
            "asserted pass": lambda value: value["samples"][0][
                "observation"
            ]["post_rewrap_payload_capture"].update(sha256="0" * 64),
            "missing sample": lambda value: value["samples"].pop(),
            "equal wrapped DEKs": lambda value: value["samples"][0][
                "observation"
            ]["new_wrapped_dek"].update(
                sha256=value["samples"][0]["observation"]["old_wrapped_dek"][
                    "sha256"
                ]
            ),
            "v1 not superseded": lambda value: value["supersedes"].update(
                status="active"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(result)
                mutate(changed)
                self.assertFalse(
                    VERIFY.valid_v2_key_rotation_result(changed, plan)
                )

    def test_key_rotation_v2_evidence_mutations_fail(self) -> None:
        mutations = {
            "changed digest": lambda observation: observation[
                "post_rewrap_payload_capture"
            ].update(sha256="0" * 64),
            "changed count": lambda observation: observation[
                "post_rewrap_payload_capture"
            ].update(
                byte_count=observation["post_rewrap_payload_capture"][
                    "byte_count"
                ]
                + 1
            ),
            "missing capture": lambda observation: observation.pop(
                "post_rewrap_payload_capture"
            ),
            "non-independent capture": lambda observation: observation[
                "post_rewrap_payload_capture"
            ].update(
                capture_id=observation["pre_rewrap_payload_capture"][
                    "capture_id"
                ]
            ),
            "equal wrapped DEKs": lambda observation: observation[
                "new_wrapped_dek"
            ].update(sha256=observation["old_wrapped_dek"]["sha256"]),
            "inconsistent assertion": lambda observation: observation.update(
                payload_ciphertext_unchanged=False
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                root = self.copy_evidence()
                path = root / VERIFY.V2_KEY_ROTATION_PATH
                result = json.loads(path.read_text(encoding="utf-8"))
                mutate(result["samples"][0]["observation"])
                path.write_text(json.dumps(result), encoding="utf-8")
                self.assertIn(
                    "invalid_v2_key_rotation_evidence",
                    self.codes(root),
                )

    def test_version_one_key_rotation_evidence_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/key-rotation.json"
        path.write_bytes(path.read_bytes() + b"\n")
        self.assertIn(
            "modified_v1_key_rotation_evidence",
            self.codes(root),
        )

    def test_missing_raw_sample_fails(self) -> None:
        root = self.copy_evidence()
        path = root / VERIFY.RESULT_FILES[0]
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"].pop()
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("wrong_sample_count", self.codes(root))

    def test_every_plan_commit_resolves_to_the_canonical_plan(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/giant-stream.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["plan_commit"] = "0" * 40
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("unresolvable_plan_commit", self.codes(root))

    def test_reconciled_plan_identifier_preserves_raw_samples(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/giant-stream.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["elapsed_ms"] += 1
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("reconciled_sample_digest_mismatch", self.codes(root))

    def test_tolerance_change_requires_review_and_prior_baseline_rerun(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/precommit.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["tolerance_history"].append(
            {
                "case": "giant-stream",
                "field": "max_elapsed_ms",
                "old": 10000,
                "new": 12000,
            }
        )
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("invalid_tolerance_change", self.codes(root))

    def test_claim_links_cover_exactly_nine_prototype_benchmark_pairs(self) -> None:
        claims = json.loads(
            (ROOT / "policy/prototype-claims.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(VERIFY.PROTOTYPES),
            {claim["prototype_id"] for claim in claims["claims"]},
        )
        self.assertEqual(9, len(claims["claims"]))
        for claim in claims["claims"]:
            self.assertTrue((ROOT / claim["prototype_path"]).is_file())
            self.assertTrue((ROOT / claim["result_path"]).is_file())

    def test_clean_clone_reproduction_covers_every_conclusion(self) -> None:
        reproduction = json.loads(
            (ROOT / "docs/research/benchmarks/reproduction.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(VERIFY.PROTOTYPES),
            {result["prototype_id"] for result in reproduction["results"]},
        )
        self.assertTrue(all(result["comparison"]["matches"] for result in reproduction["results"]))

    def test_v2_clean_clone_reconciliation_covers_exactly_27_samples(self) -> None:
        reproduction = json.loads(
            (ROOT / "docs/research/benchmarks/v2/reproduction.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(VERIFY.PROTOTYPES),
            {result["prototype_id"] for result in reproduction["results"]},
        )
        self.assertEqual(27, reproduction["sample_count"])
        self.assertEqual(
            27,
            sum(
                len(result["raw_result"]["samples"])
                for result in reproduction["results"]
            ),
        )
        self.assertTrue(
            all(
                result["comparison"]["matches"]
                for result in reproduction["results"]
            )
        )

    def mutate_v2_reproduction(self, mutate) -> set[str]:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/v2/reproduction.json"
        reproduction = json.loads(path.read_text(encoding="utf-8"))
        mutate(reproduction)
        path.write_text(json.dumps(reproduction), encoding="utf-8")
        return self.codes(root)

    def test_v2_clean_clone_status_mutation_fails(self) -> None:
        self.assertIn(
            "invalid_v2_clean_clone_reproduction",
            self.mutate_v2_reproduction(
                lambda value: value.update(clean_clone=False)
            ),
        )

    def test_v2_sample_count_mutation_fails(self) -> None:
        self.assertIn(
            "invalid_v2_reproduction_summary",
            self.mutate_v2_reproduction(
                lambda value: value.update(sample_count=26)
            ),
        )

    def test_v2_resource_provenance_mutation_fails(self) -> None:
        self.assertIn(
            "v2_clean_clone_result_mismatch",
            self.mutate_v2_reproduction(
                lambda value: value["results"][0]["raw_result"]["samples"][0][
                    "resource_accounting"
                ].update(source="")
            ),
        )

    def test_v2_resource_budget_mutation_fails(self) -> None:
        self.assertIn(
            "v2_clean_clone_result_mismatch",
            self.mutate_v2_reproduction(
                lambda value: value["results"][0]["raw_result"]["samples"][0][
                    "resource_accounting"
                ].update(budget_bytes=536870913)
            ),
        )

    def test_v2_key_rotation_digest_mutation_fails(self) -> None:
        def mutate(value) -> None:
            result = next(
                row
                for row in value["results"]
                if row["prototype_id"] == "key-rotation"
            )
            result["raw_result"]["samples"][0]["observation"][
                "post_rewrap_payload_capture"
            ]["sha256"] = "0" * 64

        self.assertIn(
            "v2_clean_clone_result_mismatch",
            self.mutate_v2_reproduction(mutate),
        )

    def test_v2_disconnect_fault_mutation_fails(self) -> None:
        def mutate(value) -> None:
            result = next(
                row
                for row in value["results"]
                if row["prototype_id"] == "decision-durability"
            )
            result["raw_result"]["samples"][0]["observation"][
                "readiness_observed"
            ] = False

        self.assertIn(
            "v2_clean_clone_result_mismatch",
            self.mutate_v2_reproduction(mutate),
        )

    def test_reproduction_recomputes_comparison_from_raw_samples(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/reproduction.json"
        reproduction = json.loads(path.read_text(encoding="utf-8"))
        reproduction["results"][0]["raw_result"]["samples"].pop()
        path.write_text(json.dumps(reproduction), encoding="utf-8")
        self.assertIn("clean_clone_result_mismatch", self.codes(root))

    def test_reproduction_requires_independent_clean_clone_evidence(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/reproduction.json"
        reproduction = json.loads(path.read_text(encoding="utf-8"))
        reproduction["clean_clone_evidence"]["independent_object_store"] = False
        path.write_text(json.dumps(reproduction), encoding="utf-8")
        self.assertIn("invalid_clean_clone_reproduction", self.codes(root))

    def test_research_manifest_marks_complete_pairs_in_review(self) -> None:
        manifest = json.loads(
            (ROOT / "policy/research-manifest.json").read_text(encoding="utf-8")
        )
        relevant = [
            row
            for row in manifest["deliverables"]
            if row["type"] in {"prototype", "benchmark"}
        ]
        self.assertEqual(18, len(relevant))
        self.assertTrue(all(row["state"] == "in-review" for row in relevant))

    def test_analyzer_matrix_requires_every_family(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"] = [
            row for row in plan["families"] if row["family"] != "external-llm"
        ]
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("missing_analyzer_family", self.codes(root))

    def test_analyzer_matrix_requires_prompt_injection_suite(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["prompt_injection"].pop("suite")
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("incomplete_analyzer_dimension", self.codes(root))

    def test_analyzer_matrix_requires_family_source_mapping(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["sources"].pop()
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("analyzer_source_coverage_mismatch", self.codes(root))

    def test_analyzer_matrix_requires_fixture_mapping(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["fixtures"] = []
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("invalid_analyzer_fixture_mapping", self.codes(root))

    def test_analyzer_matrix_requires_dataset_mapping(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["datasets"] = []
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("invalid_analyzer_dataset_mapping", self.codes(root))

    def test_analyzer_matrix_requires_metric_mapping(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["metrics"].pop()
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("analyzer_metric_threshold_mismatch", self.codes(root))

    def test_analyzer_matrix_rejects_malformed_metrics_without_exception(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["metrics"] = {"unexpected": "shape"}
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("analyzer_metric_threshold_mismatch", self.codes(root))

    def test_analyzer_matrix_requires_fixed_threshold(self) -> None:
        root = self.copy_evidence()
        path = root / "policy/analyzer-evaluation.json"
        plan = json.loads(path.read_text(encoding="utf-8"))
        plan["families"][0]["thresholds"].pop(
            next(iter(plan["families"][0]["thresholds"]))
        )
        path.write_text(json.dumps(plan), encoding="utf-8")
        self.assertIn("analyzer_metric_threshold_mismatch", self.codes(root))

    def test_postgres_result_binds_declared_lifecycle(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/postgres-storage.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["environment"]["postgres"]["port"] = 5432
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_postgres_environment", self.codes(root))

    def test_postgres_storage_requires_partition_pruning_evidence(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/postgres-storage.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"]["partition_pruning"] = False
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_postgres_observation", self.codes(root))

    def test_decision_durability_rejects_orphan_state(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/decision-durability.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"]["orphan_receipts"] = 1
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_postgres_observation", self.codes(root))

    def test_offline_replay_requires_explicit_supersession(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/offline-replay.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"]["late_revision"]["supersedes"] = None
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_postgres_observation", self.codes(root))

    def test_analyzer_isolation_enforces_finite_resource_bounds(self) -> None:
        result = RUN.analyzer_isolation(ROOT)
        self.assertTrue(result["sanitized_environment"])
        self.assertTrue(result["isolated_working_directory"])
        self.assertEqual(1, result["cpu_limit_seconds"])
        self.assertTrue(result["address_space_limit_enforced"])
        self.assertLess(result["address_space_limit_bytes"], 1 << 63)
        self.assertEqual(16, result["file_descriptor_limit"])
        self.assertTrue(result["output_limit_enforced"])
        self.assertEqual(4096, result["output_limit_bytes"])
        self.assertTrue(result["deadline_limit_enforced"])
        self.assertEqual(2, result["deadline_seconds"])
        self.assertFalse(result["network_denial_proven"])
        self.assertFalse(result["hostile_multi_tenant_isolation_proven"])

    def test_analyzer_ambient_state_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/analyzer-isolation.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"]["sanitized_environment"] = False
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_analyzer_isolation_observation", self.codes(root))

    def test_analyzer_finite_resource_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/analyzer-isolation.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"].pop("deadline_seconds")
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_analyzer_isolation_observation", self.codes(root))

    def test_analyzer_network_claim_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/analyzer-isolation.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"]["network_denial_proven"] = True
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_analyzer_isolation_observation", self.codes(root))

    def test_analyzer_hostile_tenant_claim_mutation_fails(self) -> None:
        root = self.copy_evidence()
        path = root / "docs/research/benchmarks/analyzer-isolation.json"
        result = json.loads(path.read_text(encoding="utf-8"))
        result["samples"][0]["observation"][
            "hostile_multi_tenant_isolation_proven"
        ] = True
        path.write_text(json.dumps(result), encoding="utf-8")
        self.assertIn("invalid_analyzer_isolation_observation", self.codes(root))


if __name__ == "__main__":
    unittest.main()
