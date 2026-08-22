#!/usr/bin/env python3
"""Enforce DCO signoffs on commits introduced after a recorded history boundary."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SIGNOFF = re.compile(r"(?im)^Signed-off-by:\s+[^<\n]+<[^>\n]+>\s*$")


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        text=True,
    ).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--grandfather", required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    commits = git(root, "rev-list", "--reverse", f"{arguments.base}..{arguments.head}")
    failures: list[dict[str, str]] = []
    checked = 0
    grandfathered = 0
    for commit in commits.splitlines():
        if not commit:
            continue
        if is_ancestor(root, commit, arguments.grandfather):
            grandfathered += 1
            continue
        checked += 1
        message = git(root, "show", "-s", "--format=%B", commit)
        if not SIGNOFF.search(message):
            failures.append(
                {
                    "schema_version": "1.0.0",
                    "criterion_id": "VAL-READY-025",
                    "code": "missing_dco_signoff",
                    "path": commit,
                    "message": "Commit lacks a Developer Certificate of Origin signoff",
                    "remediation_command": "git commit --amend --signoff",
                }
            )
    if failures:
        for failure in failures:
            print(json.dumps(failure, sort_keys=True), file=sys.stderr)
            if "GITHUB_ACTIONS" in __import__("os").environ:
                print(
                    f"::error title=DCO signoff required,file={failure['path']}::"
                    f"{failure['message']}; run {failure['remediation_command']}",
                    file=sys.stderr,
                )
        return 1
    print(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "criterion_id": "VAL-READY-025",
                "status": "passed",
                "checked_commits": checked,
                "grandfathered_commits": grandfathered,
                "history_boundary": arguments.grandfather,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
