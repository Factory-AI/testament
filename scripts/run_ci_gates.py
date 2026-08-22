#!/usr/bin/env python3
"""Run declared remote gates and always preserve one bounded JSON result."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


GATES = ["lint", "typecheck", "test-gate", "build", "agent-ready"]


def deliberate_failure() -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": "VAL-READY-028",
        "code": "deliberate_safe_failure",
        "path": ".github/workflows/quality.yml",
        "message": "The authorized safe failure proves remote remediation evidence",
        "remediation_command": "Run the Quality workflow with deliberate_failure=false",
    }


def write(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--deliberate-failure", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    if arguments.deliberate_failure:
        problem = deliberate_failure()
        write(arguments.artifact, problem)
        print(json.dumps(problem, sort_keys=True), file=sys.stderr)
        print(
            "::error title=VAL-READY-028 deliberate safe failure,"
            "file=.github/workflows/quality.yml,line=1::"
            f"{problem['message']}; {problem['remediation_command']}",
            file=sys.stderr,
        )
        return 1

    completed: list[str] = []
    for gate in GATES:
        process = subprocess.run(["make", gate], cwd=root)
        if process.returncode != 0:
            problem = {
                "schema_version": "1.0.0",
                "criterion_id": "VAL-READY-027",
                "code": "remote_gate_failed",
                "path": "Makefile",
                "message": f"Declared remote gate failed: make {gate}",
                "remediation_command": f"make {gate}",
                "completed_gates": completed,
            }
            write(arguments.artifact, problem)
            print(json.dumps(problem, sort_keys=True), file=sys.stderr)
            return process.returncode
        completed.append(gate)

    result: dict[str, object] = {
        "schema_version": "1.0.0",
        "criterion_id": "VAL-READY-027",
        "status": "passed",
        "completed_gates": completed,
    }
    write(arguments.artifact, result)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
