from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS_SPEC = importlib.util.spec_from_file_location(
    "prototype_decision_durability",
    ROOT / "scripts" / "prototype_decision_durability.py",
)
assert HARNESS_SPEC and HARNESS_SPEC.loader
HARNESS = importlib.util.module_from_spec(HARNESS_SPEC)
HARNESS_SPEC.loader.exec_module(HARNESS)

VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_prototypes",
    ROOT / "scripts" / "verify_prototypes.py",
)
assert VERIFY_SPEC and VERIFY_SPEC.loader
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


def passing_observation() -> dict[str, object]:
    return {
        "fault_type": "postgresql-backend-termination",
        "fault_session_id": "testament-fault-0123456789abcdef",
        "fault_backend_pid": 123,
        "readiness_marker": (
            "TESTAMENT_FAULT_READY:123:testament-fault-0123456789abcdef"
        ),
        "readiness_observed": True,
        "transaction_active_before_injection": True,
        "backend_identity_matched": True,
        "termination_acknowledged": True,
        "explicit_rollback_issued": False,
        "client_connection_lost": True,
        "fault_client_exit_code": 2,
        "backend_disappeared": True,
        "verification_connection_fresh": True,
        "automatic_rollback_verified": True,
        "decisions": 1,
        "audits": 1,
        "receipts": 1,
        "faulted_decisions": 0,
        "faulted_audits": 0,
        "faulted_receipts": 0,
        "faulted_rows": 0,
        "orphan_audits": 0,
        "orphan_receipts": 0,
        "postgres_version": "17.11",
        "port": 5440,
    }


class DecisionDurabilityEvidenceTest(unittest.TestCase):
    def test_fault_transaction_has_no_explicit_rollback(self) -> None:
        self.assertNotIn(
            "ROLLBACK",
            HARNESS.FAULT_TRANSACTION_SQL.upper(),
        )
        self.assertIn("TESTAMENT_FAULT_READY", HARNESS.FAULT_TRANSACTION_SQL)
        self.assertIn("pg_sleep", HARNESS.FAULT_TRANSACTION_SQL)

    def test_disconnect_observation_is_accepted(self) -> None:
        observation = passing_observation()
        self.assertTrue(HARNESS.accepted_observation(observation))
        self.assertTrue(VERIFY.valid_v2_decision_durability_observation(observation))

    def test_disconnect_evidence_mutations_are_rejected(self) -> None:
        mutations = {
            "explicit rollback": lambda value: value.update(
                explicit_rollback_issued=True
            ),
            "missing readiness": lambda value: value.update(
                readiness_marker=None,
                readiness_observed=False,
            ),
            "inactive transaction": lambda value: value.update(
                transaction_active_before_injection=False
            ),
            "wrong backend": lambda value: value.update(
                backend_identity_matched=False
            ),
            "failed termination": lambda value: value.update(
                termination_acknowledged=False
            ),
            "normal client exit": lambda value: value.update(
                fault_client_exit_code=0
            ),
            "connection retained": lambda value: value.update(
                client_connection_lost=False
            ),
            "surviving backend": lambda value: value.update(
                backend_disappeared=False
            ),
            "reused verification connection": lambda value: value.update(
                verification_connection_fresh=False
            ),
            "false rollback verification": lambda value: value.update(
                automatic_rollback_verified=False
            ),
            "faulted decision": lambda value: value.update(
                faulted_decisions=1,
                faulted_rows=1,
            ),
            "faulted audit": lambda value: value.update(
                faulted_audits=1,
                faulted_rows=1,
            ),
            "faulted receipt": lambda value: value.update(
                faulted_receipts=1,
                faulted_rows=1,
            ),
            "orphan audit": lambda value: value.update(orphan_audits=1),
            "orphan receipt": lambda value: value.update(orphan_receipts=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(passing_observation())
                mutate(changed)
                self.assertFalse(HARNESS.accepted_observation(changed))
                self.assertFalse(
                    VERIFY.valid_v2_decision_durability_observation(changed)
                )

    def test_committed_v2_result_recomputes_all_samples(self) -> None:
        plan = json.loads(
            (ROOT / VERIFY.SUCCESSOR_PLAN_PATH).read_text(encoding="utf-8")
        )
        case_plan = next(
            row for row in plan["cases"] if row["id"] == "decision-durability"
        )
        observation = passing_observation()
        observation["worker_completed"] = True
        accounting = {
            "accounting_version": "2.0.0",
            "scope": "postgres_container_cgroup",
            "metric": "peak_container_cgroup_resident_bytes",
            "source": "docker_stats_container_cgroup",
            "target": "container_id:synthetic",
            "isolation": "fresh_service_lifecycle_and_worker_process_group",
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
            "feature_id": "decision-durability-disconnect-fault-evidence",
            "validation_id": "VAL-READY-014",
            "prototype_id": "decision-durability",
            "benchmark_id": "decision-durability-benchmark",
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
                "path": "docs/research/benchmarks/decision-durability.json",
                "version": "1.0.0",
                "sha256": VERIFY.V1_DECISION_DURABILITY_SHA256,
                "status": "superseded-evidence",
                "preserved": True,
            },
        }
        self.assertTrue(
            VERIFY.valid_v2_decision_durability_result(result, plan)
        )
        for name, mutate in {
            "asserted pass": lambda value: value["samples"][0][
                "observation"
            ].update(termination_acknowledged=False),
            "missing sample": lambda value: value["samples"].pop(),
            "normal client exit": lambda value: value["samples"][0][
                "observation"
            ].update(fault_client_exit_code=0),
            "v1 not superseded": lambda value: value["supersedes"].update(
                status="active"
            ),
        }.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(result)
                mutate(changed)
                self.assertFalse(
                    VERIFY.valid_v2_decision_durability_result(changed, plan)
                )


if __name__ == "__main__":
    unittest.main()
