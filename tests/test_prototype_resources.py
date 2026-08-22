from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prototype_resources import (  # noqa: E402
    AccountingError,
    ServicesManifest,
    observe_local_process,
    observe_postgres_process,
    validate_accounting,
)
from verify_prototypes import valid_v2_resource_sample  # noqa: E402


class PrototypeResourceAccountingTest(unittest.TestCase):
    def test_successor_plan_preserves_v1_budgets_and_precommits_findings(self) -> None:
        v1 = json.loads(
            (ROOT / "docs/research/benchmarks/precommit.json").read_text()
        )
        v2 = json.loads(
            (ROOT / "docs/research/benchmarks/precommit-v2.json").read_text()
        )
        self.assertEqual("2.0.0", v2["version"])
        self.assertEqual(
            "cfdf43bb49f3802137dc0ae887314ab7a8a01f58",
            v2["supersedes"]["commit"],
        )
        self.assertEqual(
            {"F-001", "F-002", "F-003"},
            {row["finding_id"] for row in v2["remediations"]},
        )
        old = {
            row["id"]: (row["sample_count"], row["budgets"], row["tolerances"])
            for row in v1["cases"]
        }
        new = {
            row["id"]: (row["sample_count"], row["budgets"], row["tolerances"])
            for row in v2["cases"]
        }
        self.assertEqual(old, new)
        self.assertTrue(
            all(
                row["budgets"]["max_process_rss_bytes"] == 536870912
                for row in v2["cases"]
            )
        )

    def test_external_observer_counts_child_allocation(self) -> None:
        child_bytes = 48 * 1024 * 1024
        script = (
            "import subprocess,sys;"
            f"code='import time; value=bytearray({child_bytes}); time.sleep(0.8)';"
            "child=subprocess.Popen([sys.executable,'-c',code]);"
            "child.wait();"
            "print('{\"ok\":true}')"
        )
        result = observe_local_process(
            [sys.executable, "-c", script],
            cwd=ROOT,
            budget_bytes=256 * 1024 * 1024,
            hard_limit_bytes=256 * 1024 * 1024,
            timeout_ms=5000,
            poll_interval_seconds=0.01,
        )
        self.assertEqual(0, result.returncode)
        self.assertGreaterEqual(
            result.accounting["peak_rss_bytes"], child_bytes
        )
        self.assertTrue(result.accounting["descendants_included"])
        self.assertEqual("fresh_process_group", result.accounting["isolation"])
        self.assertTrue(result.accounting["within_budget"])

    def test_over_budget_worker_is_failed_and_terminated(self) -> None:
        script = "import time; value=bytearray(32*1024*1024); time.sleep(5)"
        result = observe_local_process(
            [sys.executable, "-c", script],
            cwd=ROOT,
            budget_bytes=8 * 1024 * 1024,
            hard_limit_bytes=8 * 1024 * 1024,
            timeout_ms=5000,
            poll_interval_seconds=0.01,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(result.limit_exceeded)
        self.assertFalse(result.accounting["within_budget"])
        self.assertGreater(
            result.accounting["peak_rss_bytes"],
            result.accounting["budget_bytes"],
        )

    def test_descendant_cannot_outlive_worker_sample(self) -> None:
        script = (
            "import json,subprocess,sys,time;"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)']);"
            "print(json.dumps({'child_pid':child.pid}),flush=True);"
            "time.sleep(0.3)"
        )
        result = observe_local_process(
            [sys.executable, "-c", script],
            cwd=ROOT,
            budget_bytes=256 * 1024 * 1024,
            hard_limit_bytes=256 * 1024 * 1024,
            timeout_ms=5000,
            poll_interval_seconds=0.01,
        )
        child_pid = json.loads(result.stdout)["child_pid"]
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            return
        # Linux may briefly retain the terminated grandchild as a zombie until
        # the runner's init process reaps it. A zombie cannot execute or retain
        # the sampled allocation, so it satisfies the no-outliving-worker
        # contract even though kill(2) still resolves the PID.
        status = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(child_pid)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        self.assertTrue(
            not status or status.startswith("Z"),
            f"child remains live: {status}",
        )

    def valid_accounting(self) -> dict[str, object]:
        return {
            "accounting_version": "2.0.0",
            "scope": "worker_descendant_tree",
            "metric": "aggregate_peak_resident_bytes",
            "source": "external_ps_process_table",
            "target": "worker_pid:123",
            "isolation": "fresh_process_group",
            "descendants_included": True,
            "peak_rss_bytes": 1024,
            "budget_bytes": 2048,
            "hard_limit_bytes": 2048,
            "within_budget": True,
        }

    def assert_invalid(self, mutation: dict[str, object]) -> None:
        value = self.valid_accounting()
        value.update(mutation)
        with self.assertRaises(AccountingError):
            validate_accounting(value)

    def test_missing_source_is_rejected(self) -> None:
        self.assert_invalid({"source": ""})

    def test_non_isolated_sample_is_rejected(self) -> None:
        self.assert_invalid({"isolation": "shared_process_group"})

    def test_parent_rusage_scope_is_rejected(self) -> None:
        self.assert_invalid(
            {
                "scope": "parent_process",
                "source": "resource.getrusage(RUSAGE_SELF)",
            }
        )

    def test_inconsistent_asserted_status_is_rejected(self) -> None:
        self.assert_invalid(
            {
                "peak_rss_bytes": 4096,
                "budget_bytes": 2048,
                "hard_limit_bytes": 2048,
                "within_budget": True,
            }
        )

    def test_v2_sample_rejects_legacy_parent_only_field(self) -> None:
        sample = {
            "elapsed_ms": 1,
            "process_max_rss_bytes": 1024,
            "resource_accounting": self.valid_accounting(),
            "observation": {"worker_completed": True},
        }
        self.assertFalse(
            valid_v2_resource_sample(
                sample,
                {
                    "max_elapsed_ms": 10000,
                    "max_process_rss_bytes": 2048,
                },
                "giant-stream",
            )
        )

    def test_v2_sample_recomputes_asserted_status(self) -> None:
        accounting = self.valid_accounting()
        accounting["within_budget"] = False
        sample = {
            "elapsed_ms": 1,
            "resource_accounting": accounting,
            "observation": {"worker_completed": True},
        }
        self.assertFalse(
            valid_v2_resource_sample(
                sample,
                {
                    "max_elapsed_ms": 10000,
                    "max_process_rss_bytes": 2048,
                },
                "giant-stream",
            )
        )

    @unittest.skipUnless(
        os.environ.get("TESTAMENT_SERVICES_MANIFEST"),
        "set TESTAMENT_SERVICES_MANIFEST to run PostgreSQL lifecycle integration",
    )
    def test_postgres_sample_uses_manifest_and_container_cgroup(self) -> None:
        manifest = ServicesManifest.from_path(
            Path(os.environ["TESTAMENT_SERVICES_MANIFEST"])
        )
        command = [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "testament",
            "-d",
            "testament",
            "-p",
            "5440",
            "-Atqc",
            "SELECT pg_sleep(1), current_setting('server_version');",
        ]
        result = observe_postgres_process(
            command,
            cwd=ROOT,
            manifest=manifest,
            budget_bytes=536870912,
            hard_limit_bytes=536870912,
            timeout_ms=15000,
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("17.", result.stdout)
        self.assertEqual("postgres_container_cgroup", result.accounting["scope"])
        self.assertEqual(
            "docker_stats_container_cgroup",
            result.accounting["source"],
        )
        self.assertEqual(
            "fresh_service_lifecycle_and_worker_process_group",
            result.accounting["isolation"],
        )
        self.assertTrue(result.accounting["within_budget"])
        running = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "-q", "postgres"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual("", running.stdout.strip())


if __name__ == "__main__":
    unittest.main()
