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


VERIFY = load_module("verify_readiness", "scripts/verify_readiness.py")
WORKFLOW = load_module("workflow", "scripts/workflow.py")


class ReadinessContractTest(unittest.TestCase):
    def copy_repository(self) -> Path:
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

    def test_complete_readiness_contract_passes(self) -> None:
        self.assertEqual([], VERIFY.validate(ROOT))

    def test_postgres_image_and_port_drift_fail(self) -> None:
        root = self.copy_repository()
        compose = root / "compose.yaml"
        compose.write_text(
            compose.read_text(encoding="utf-8")
            .replace("postgres:17.11-bookworm@sha256:", "postgres:17.11-bookworm:")
            .replace(
                '"127.0.0.1:${TESTAMENT_POSTGRES_PORT:-5440}:5440"',
                '"127.0.0.1:${TESTAMENT_POSTGRES_PORT:-5432}:5432"',
            ),
            encoding="utf-8",
        )
        codes = self.codes(root)
        self.assertIn("unpinned_postgres_image", codes)
        self.assertIn("postgres_port_drift", codes)

    def test_missing_scoped_skill_fails(self) -> None:
        root = self.copy_repository()
        (root / ".agents" / "skills" / "incident" / "SKILL.md").unlink()
        self.assertIn("missing_agent_skill", self.codes(root))

    def test_extra_lowercase_devcontainer_stage_fails(self) -> None:
        root = self.copy_repository()
        path = root / ".devcontainer/Dockerfile"
        with path.open("a", encoding="utf-8") as dockerfile:
            dockerfile.write("\n  from malicious.example/image@sha256:" + "0" * 64 + "\n")
        self.assertIn("devcontainer_toolchain_drift", self.codes(root))

    def test_duplicate_workflow_entry_fails(self) -> None:
        root = self.copy_repository()
        path = root / "policy/repository-contracts.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["commands"].append(
            {"id": "setup", "entry_point": "make alternate-setup"}
        )
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn("incomplete_workflow_index", self.codes(root))

    def test_setup_interruption_is_actionable_and_rerunnable(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "policy").mkdir()
        (root / "policy" / "toolchain.json").write_bytes(
            (ROOT / "policy" / "toolchain.json").read_bytes()
        )

        with self.assertRaises(WORKFLOW.WorkflowFailure) as captured:
            WORKFLOW.setup(
                root,
                observed_versions=WORKFLOW.expected_versions(root),
                failpoint="after-version-check",
            )
        failure = captured.exception.problem
        self.assertEqual(
            {
                "schema_version",
                "criterion_id",
                "code",
                "path",
                "message",
                "remediation_command",
            },
            set(failure),
        )
        self.assertFalse((root / ".testament" / "setup-state.json").exists())

        result = WORKFLOW.setup(
            root,
            observed_versions=WORKFLOW.expected_versions(root),
        )
        state = json.loads(
            (root / ".testament" / "setup-state.json").read_text(encoding="utf-8")
        )
        self.assertEqual("ready", result["status"])
        self.assertEqual("ready", state["status"])
        self.assertEqual(state, WORKFLOW.setup(root, WORKFLOW.expected_versions(root)))

    def test_setup_refuses_symlinked_state_directory(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "repository"
        outside = Path(temporary.name) / "outside"
        (root / "policy").mkdir(parents=True)
        outside.mkdir()
        (root / "policy" / "toolchain.json").write_bytes(
            (ROOT / "policy" / "toolchain.json").read_bytes()
        )
        (root / ".testament").symlink_to(outside, target_is_directory=True)

        with self.assertRaises(WORKFLOW.WorkflowFailure) as captured:
            WORKFLOW.setup(root, WORKFLOW.expected_versions(root))

        self.assertEqual("unsafe_state_directory", captured.exception.problem["code"])
        self.assertEqual([], list(outside.iterdir()))


if __name__ == "__main__":
    unittest.main()
