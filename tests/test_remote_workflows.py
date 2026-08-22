from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load_module("verify_remote_workflows", "scripts/verify_remote_workflows.py")
CI = load_module("run_ci_gates", "scripts/run_ci_gates.py")
MAINTENANCE = load_module("maintenance_issues", "scripts/maintenance_issues.py")


class RemoteWorkflowContractTest(unittest.TestCase):
    def copy_contract(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative in VERIFY.REQUIRED_PATHS:
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        return root

    def codes(self, root: Path) -> set[str]:
        return {problem["code"] for problem in VERIFY.validate(root)}

    def test_complete_remote_workflow_contract_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_unpinned_action_and_write_all_permissions_fail(self) -> None:
        root = self.copy_contract()
        workflow = root / ".github/workflows/quality.yml"
        text = workflow.read_text(encoding="utf-8")
        text = text.replace(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "actions/checkout@v4",
        ).replace("permissions:\n  contents: read", "permissions: write-all")
        workflow.write_text(text, encoding="utf-8")
        codes = self.codes(root)
        self.assertIn("unpinned_action", codes)
        self.assertIn("excessive_workflow_permissions", codes)

    def test_required_trigger_mutation_fails(self) -> None:
        root = self.copy_contract()
        workflow = root / ".github/workflows/quality.yml"
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                "  schedule:\n    - cron: '17 4 * * 2'",
                "",
            ),
            encoding="utf-8",
        )
        self.assertIn("incomplete_workflow_triggers", self.codes(root))

    def test_issue_form_field_mutation_fails(self) -> None:
        root = self.copy_contract()
        form = root / ".github/ISSUE_TEMPLATE/work-item.yml"
        form.write_text(
            form.read_text(encoding="utf-8").replace(
                "id: observability",
                "id: missing-observability",
            ),
            encoding="utf-8",
        )
        self.assertIn("incomplete_issue_form", self.codes(root))

    def test_issue_and_pr_metadata_require_nonempty_stable_sections(self) -> None:
        issue_body = "\n".join(
            f"### {heading}\n\nvalue" for heading in VERIFY.ISSUE_HEADINGS
        )
        pr_body = "\n".join(
            f"## {heading}\n\nvalue" for heading in VERIFY.PR_HEADINGS
        )
        self.assertEqual([], VERIFY.metadata_problems("issue", issue_body))
        self.assertEqual([], VERIFY.metadata_problems("pull_request", pr_body))
        self.assertEqual(
            ["observability"],
            VERIFY.metadata_problems(
                "issue",
                issue_body.replace("### Observability\n\nvalue", "### Observability\n\n_None_"),
            ),
        )
        self.assertEqual(
            ["agent authorship"],
            VERIFY.metadata_problems(
                "pull_request",
                pr_body.replace(
                    "## Agent authorship\n\nvalue",
                    "## Agent authorship\n\n",
                ),
            ),
        )

    def test_publication_scan_is_repository_bounded_and_detects_findings(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repository"
        root.mkdir()
        safe = root / "safe.txt"
        safe.write_text("ordinary content\n", encoding="utf-8")
        outside = Path(temporary.name) / "outside.txt"
        outside.write_text("unrelated content\n", encoding="utf-8")
        self.assertEqual([], VERIFY.scan_publication_paths(root, [safe]))
        with self.assertRaises(ValueError):
            VERIFY.scan_publication_paths(root, [outside])

        token = "gh" + "p_" + ("a" * 36)
        safe.write_text(f"credential={token}\n", encoding="utf-8")
        findings = VERIFY.scan_publication_paths(root, [safe])
        self.assertEqual("github_token", findings[0]["code"])
        self.assertEqual("safe.txt", findings[0]["path"])

    def test_publication_allowlist_is_exact_and_digest_bound(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "policy").mkdir()
        path = root / "tests" / "test_corpus.py"
        path.parent.mkdir()
        known_canary = "AK" + "IAIOSFODNN7EXAMPLE"
        path.write_text("\n" * 170 + known_canary + "\n", encoding="utf-8")
        contract = json.loads(
            (ROOT / "policy/remote-workflows.json").read_text(encoding="utf-8")
        )
        (root / "policy/remote-workflows.json").write_text(
            json.dumps(contract),
            encoding="utf-8",
        )
        self.assertEqual([], VERIFY.scan_publication_paths(root, [path]))
        changed_canary = "AK" + "IAIOSFODNN7EXAMPLF"
        path.write_text("\n" * 170 + changed_canary + "\n", encoding="utf-8")
        self.assertEqual(
            ["aws_access_key"],
            [
                finding["code"]
                for finding in VERIFY.scan_publication_paths(root, [path])
            ],
        )

    def test_dco_grandfather_boundary_rejects_new_unsigned_commit(self) -> None:
        messages = [
            {
                "sha": "historical",
                "message": "Historical commit",
                "grandfathered": True,
            },
            {
                "sha": "signed",
                "message": (
                    "Signed contribution\n\n"
                    "Signed-off-by: Eno Reyes <enoreyes@gmail.com>"
                ),
                "grandfathered": False,
            },
        ]
        self.assertEqual([], VERIFY.unsigned_commits(messages))
        messages.append(
            {
                "sha": "unsigned",
                "message": "Unsigned disposable contribution",
                "grandfathered": False,
            }
        )
        self.assertEqual(["unsigned"], VERIFY.unsigned_commits(messages))

    def test_deliberate_failure_is_actionable(self) -> None:
        problem = CI.deliberate_failure()
        self.assertEqual(
            {
                "schema_version",
                "criterion_id",
                "code",
                "path",
                "message",
                "remediation_command",
            },
            set(problem),
        )
        self.assertEqual("VAL-READY-028", problem["criterion_id"])

    def test_maintenance_specs_preserve_required_ownership_and_evidence(self) -> None:
        trademark = MAINTENANCE.issue_spec("trademark-review", "run")
        self.assertEqual(["enoreyes"], trademark["assignees"])
        self.assertIn("USPTO", trademark["body"])
        self.assertIn("WIPO", trademark["body"])
        self.assertIn("qualified trademark review", trademark["body"].lower())
        self.assertIn("non-blocking", trademark["body"].lower())

        bootstrap = MAINTENANCE.issue_spec("single-maintainer-bootstrap", "run")
        self.assertEqual(["enoreyes"], bootstrap["assignees"])
        self.assertIn("2026-09-30", bootstrap["body"])
        self.assertIn("no access change", bootstrap["body"].lower())
        self.assertIn("zero readiness credit", bootstrap["body"].lower())

    def test_maintenance_dedup_selects_one_marker(self) -> None:
        issues = [
            {"number": 1, "body": "other", "state": "open"},
            {
                "number": 2,
                "body": "<!-- testament-maintenance:trademark-review -->",
                "state": "closed",
            },
        ]
        self.assertEqual(
            2,
            MAINTENANCE.find_existing(
                issues,
                "<!-- testament-maintenance:trademark-review -->",
            )["number"],
        )


if __name__ == "__main__":
    unittest.main()
