#!/usr/bin/env python3
"""Deterministic, recoverable repository workflow entry points."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"
STATE_PATH = Path(".testament/setup-state.json")
PROBES = {
    "go": ["go", "version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "python": ["python3", "--version"],
    "docker": ["docker", "--version"],
    "docker-compose": ["docker", "compose", "version"],
    "git": ["git", "--version"],
}


class WorkflowFailure(Exception):
    def __init__(self, problem: dict[str, str]):
        super().__init__(problem["message"])
        self.problem = problem


def issue(
    criterion_id: str,
    code: str,
    path: str,
    message: str,
    remediation_command: str,
) -> dict[str, str]:
    return {
        "schema_version": SCHEMA_VERSION,
        "criterion_id": criterion_id,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": remediation_command,
    }


def load_toolchain(root: Path) -> dict[str, Any]:
    path = root / "policy/toolchain.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowFailure(
            issue(
                "VAL-READY-020",
                "invalid_toolchain_contract",
                "policy/toolchain.json",
                str(error),
                "git restore policy/toolchain.json && make setup",
            )
        ) from error
    if not isinstance(value, dict) or not isinstance(value.get("tools"), list):
        raise WorkflowFailure(
            issue(
                "VAL-READY-020",
                "invalid_toolchain_contract",
                "policy/toolchain.json",
                "Toolchain contract must be an object with a tools array",
                "make verify-readiness",
            )
        )
    return value


def expected_versions(root: Path) -> dict[str, str]:
    contract = load_toolchain(root)
    return {
        item["id"]: item["version"]
        for item in contract["tools"]
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("version"), str)
    }


def normalize_version(tool: str, output: str) -> str:
    patterns = {
        "go": r"\bgo([0-9]+\.[0-9]+\.[0-9]+)\b",
        "node": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
        "npm": r"([0-9]+\.[0-9]+\.[0-9]+)",
        "python": r"Python ([0-9]+\.[0-9]+\.[0-9]+)",
        "docker": r"Docker version ([0-9]+\.[0-9]+\.[0-9]+)",
        "docker-compose": r"Docker Compose version v?([0-9]+\.[0-9]+\.[0-9]+)",
        "git": r"git version ([0-9]+\.[0-9]+\.[0-9]+)",
    }
    match = re.search(patterns[tool], output.strip())
    if not match:
        raise WorkflowFailure(
            issue(
                "VAL-READY-020",
                "unrecognized_tool_version",
                "policy/toolchain.json",
                f"Could not parse {tool} version from its declared probe",
                f"install the pinned {tool} version and run make setup",
            )
        )
    return match.group(1)


def probe_versions() -> dict[str, str]:
    def run_probe(tool: str, command: list[str]) -> str:
        try:
            process = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise WorkflowFailure(
                issue(
                    "VAL-READY-020",
                    "tool_probe_failed",
                    "policy/toolchain.json",
                    f"{tool} probe failed: {error}",
                    f"install the pinned {tool} version and run make setup",
                )
            ) from error
        return normalize_version(
            tool, process.stdout if process.stdout else process.stderr
        )

    with ThreadPoolExecutor(max_workers=len(PROBES)) as executor:
        futures = {
            tool: executor.submit(run_probe, tool, command)
            for tool, command in PROBES.items()
        }
        return {tool: futures[tool].result() for tool in PROBES}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise WorkflowFailure(
            issue(
                "VAL-READY-021",
                "unsafe_state_directory",
                str(path.parent),
                "Setup state directory must not be a symbolic link",
                f"replace {path.parent} with a repository-local directory and run make setup",
            )
        )
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(value)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def setup(
    root: Path,
    observed_versions: dict[str, str] | None = None,
    failpoint: str | None = None,
) -> dict[str, Any]:
    expected = expected_versions(root)
    observed = probe_versions() if observed_versions is None else observed_versions
    for tool in sorted(expected):
        actual = observed.get(tool)
        if actual != expected[tool]:
            raise WorkflowFailure(
                issue(
                    "VAL-READY-020",
                    "tool_version_mismatch",
                    "policy/toolchain.json",
                    f"{tool} must be {expected[tool]}, observed {actual or 'missing'}",
                    f"install {tool} {expected[tool]} and run make setup",
                )
            )

    selected_failpoint = failpoint or os.environ.get("TESTAMENT_SETUP_FAILPOINT")
    if selected_failpoint == "after-version-check":
        raise WorkflowFailure(
            issue(
                "VAL-READY-021",
                "setup_interrupted",
                ".testament/setup-state.json",
                "Setup stopped at the declared safe failpoint before state commit",
                "unset TESTAMENT_SETUP_FAILPOINT && make setup",
            )
        )
    if selected_failpoint:
        raise WorkflowFailure(
            issue(
                "VAL-READY-021",
                "unknown_setup_failpoint",
                "TESTAMENT_SETUP_FAILPOINT",
                f"Unknown setup failpoint: {selected_failpoint}",
                "unset TESTAMENT_SETUP_FAILPOINT && make setup",
            )
        )

    toolchain_bytes = (root / "policy/toolchain.json").read_bytes()
    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "toolchain_sha256": hashlib.sha256(toolchain_bytes).hexdigest(),
        "versions": {key: observed[key] for key in sorted(observed)},
        "services_started": [],
    }
    path = root / STATE_PATH
    serialized = canonical_json(state)
    if path.is_symlink() or not path.is_file() or path.read_text(encoding="utf-8") != serialized:
        atomic_write(path, serialized)
    return state


def doctor(root: Path) -> dict[str, Any]:
    state = setup(root)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "setup": state,
        "recovery_command": "make setup && make doctor",
    }


def no_op_workflow(name: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "not-applicable",
        "workflow": name,
        "message": f"{name} has no mutable implementation state in the research milestone",
    }


def blocked_workflow(name: str) -> dict[str, str]:
    return issue(
        "VAL-READY-021",
        f"{name}_blocked_by_research_gate",
        "docs/workflows.md",
        f"{name} is blocked until the research candidate, formal readiness report, and external seal pass",
        "make agent-ready",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "workflow",
        choices=["setup", "doctor", "migrate", "release", "rollback", "incident"],
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    try:
        if arguments.workflow == "setup":
            result = setup(root)
        elif arguments.workflow == "doctor":
            result = doctor(root)
        elif arguments.workflow in {"migrate", "incident"}:
            result = no_op_workflow(arguments.workflow)
        else:
            raise WorkflowFailure(blocked_workflow(arguments.workflow))
    except WorkflowFailure as error:
        print(canonical_json(error.problem), file=sys.stderr, end="")
        return 2
    print(canonical_json(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
