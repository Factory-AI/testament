#!/usr/bin/env python3
"""Validate deterministic repository, environment, and agent contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


CRITERIA = [
    "VAL-READY-020",
    "VAL-READY-021",
    "VAL-READY-022",
    "VAL-READY-023",
    "VAL-READY-024",
]
POSTGRES_IMAGE = (
    "postgres:17.11-bookworm@"
    "sha256:84560e3b9c6874893fc4e2854f5dc3e7c1a37bc9d1dfd7a8c641310ae22ba5ad"
)
SKILLS = [
    "research",
    "development",
    "adapters",
    "analyzers",
    "policy",
    "ui",
    "qa",
    "release",
    "incident",
    "readiness",
]
BASE_REQUIRED_PATHS = [
    ".devcontainer/devcontainer.json",
    ".devcontainer/Dockerfile",
    ".go-version",
    ".nvmrc",
    ".tool-versions",
    "AGENTS.md",
    "Makefile",
    "README.md",
    "compose.yaml",
    "docs/agent-guide.md",
    "docs/workflows.md",
    "generated/contract-index.json",
    "policy/architecture.json",
    "policy/readiness.json",
    "policy/repository-contracts.json",
    "policy/toolchain.json",
    "schemas/actionable-error.schema.json",
    "schemas/repository-contracts.schema.json",
    "schemas/toolchain.schema.json",
    "scripts/verify_readiness.py",
    "scripts/workflow.py",
]
REQUIRED_PATHS = BASE_REQUIRED_PATHS + [
    f".agents/skills/{name}/SKILL.md" for name in SKILLS
]


def issue(
    criterion_id: str,
    code: str,
    path: str,
    message: str,
    remediation_command: str,
) -> dict[str, str]:
    return {
        "schema_version": "1.0.0",
        "criterion_id": criterion_id,
        "code": code,
        "path": path,
        "message": message,
        "remediation_command": remediation_command,
    }


def load_json(
    root: Path,
    relative: str,
    criterion_id: str,
    problems: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        problems.append(
            issue(
                criterion_id,
                "invalid_json",
                relative,
                str(error),
                "make generate && make verify-readiness",
            )
        )
        return {}
    if not isinstance(value, dict):
        problems.append(
            issue(
                criterion_id,
                "invalid_contract_shape",
                relative,
                "Contract root must be a JSON object",
                f"repair {relative} and run make verify-readiness",
            )
        )
        return {}
    return value


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generated_index(root: Path) -> dict[str, Any]:
    manifest = json.loads(
        (root / "policy/repository-contracts.json").read_text(encoding="utf-8")
    )
    contracts = []
    for contract in sorted(manifest["contracts"], key=lambda item: item["id"]):
        machine = root / contract["machine_path"]
        contracts.append(
            {
                "id": contract["id"],
                "version": contract["version"],
                "machine_path": contract["machine_path"],
                "machine_sha256": digest(machine),
                "human_path": contract["human_path"],
            }
        )
    return {
        "schema_version": "1.0.0",
        "source": "policy/repository-contracts.json",
        "source_sha256": digest(root / "policy/repository-contracts.json"),
        "contracts": contracts,
    }


def write_index(root: Path) -> None:
    output = root / "generated/contract-index.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink():
        raise OSError("generated output directory must not be a symbolic link")
    value = json.dumps(generated_index(root), indent=2, sort_keys=True) + "\n"
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(value)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, output)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def validate(root: Path) -> list[dict[str, str]]:
    problems: list[dict[str, str]] = []
    for relative in REQUIRED_PATHS:
        if not (root / relative).is_file():
            code = (
                "missing_agent_skill"
                if relative.startswith(".agents/skills/")
                else "missing_readiness_path"
            )
            problems.append(
                issue(
                    "VAL-READY-023"
                    if code == "missing_agent_skill"
                    else "VAL-READY-020",
                    code,
                    relative,
                    f"Required readiness path is missing: {relative}",
                    f"restore {relative} and run make verify-readiness",
                )
            )

    toolchain = load_json(root, "policy/toolchain.json", "VAL-READY-022", problems)
    tools = toolchain.get("tools", [])
    if not isinstance(tools, list):
        tools = []
    expected_tools = {
        "go": "1.26.4",
        "node": "22.19.0",
        "npm": "10.9.3",
        "python": "3.14.7",
        "docker": "28.5.1",
        "docker-compose": "2.40.3",
        "git": "2.50.1",
    }
    actual_tools = {
        item.get("id"): item.get("version")
        for item in tools
        if isinstance(item, dict)
    }
    if actual_tools != expected_tools:
        problems.append(
            issue(
                "VAL-READY-022",
                "toolchain_version_drift",
                "policy/toolchain.json",
                "Tool versions differ from the pinned host contract",
                "restore policy/toolchain.json and run make setup",
            )
        )

    try:
        compose_process = subprocess.run(
            [
                "docker",
                "compose",
                "--project-directory",
                str(root),
                "-f",
                str(root / "compose.yaml"),
                "config",
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        compose_config = json.loads(compose_process.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        compose_config = {}
        problems.append(
            issue(
                "VAL-READY-022",
                "invalid_compose_contract",
                "compose.yaml",
                f"Compose configuration did not resolve: {error}",
                "repair compose.yaml and run docker compose config",
            )
        )
    postgres = compose_config.get("services", {}).get("postgres", {})
    if postgres.get("image") != POSTGRES_IMAGE:
        problems.append(
            issue(
                "VAL-READY-022",
                "unpinned_postgres_image",
                "compose.yaml",
                "PostgreSQL must use the approved 17.11 multi-platform image digest",
                "restore the pinned postgres image in compose.yaml",
            )
        )
    ports = postgres.get("ports", [])
    port_valid = (
        len(ports) == 1
        and ports[0].get("host_ip") == "127.0.0.1"
        and str(ports[0].get("published")) == "5440"
        and ports[0].get("target") == 5440
    )
    health_test = postgres.get("healthcheck", {}).get("test", [])
    health_valid = health_test == [
        "CMD-SHELL",
        "pg_isready -U testament -d testament -p 5440",
    ]
    if not port_valid or not health_valid:
        problems.append(
            issue(
                "VAL-READY-022",
                "postgres_port_drift",
                "compose.yaml",
                "PostgreSQL host, container, and health ports must all be 5440",
                "restore port 5440 in compose.yaml and run make verify-readiness",
            )
        )

    devcontainer = load_json(
        root, ".devcontainer/devcontainer.json", "VAL-READY-022", problems
    )
    features = devcontainer.get("features", {})
    expected_features = {
        "ghcr.io/devcontainers/features/node@sha256:8c0de46939b61958041700ee89e3493f3b2e4131a06dc46b4d9423427d06e5f6": {
            "version": "22.19.0",
            "nodeGypDependencies": False,
        },
        "ghcr.io/devcontainers/features/python@sha256:fbcad6955caeecc5ad3f7886baf652e25cba5225a6c4c2287c536de2e5607511": {
            "version": "3.14.7",
            "installTools": False,
        },
        "ghcr.io/devcontainers/features/git@sha256:fd75977de13a9979000e0e78baf949adb0ca71d2398995fa22e0a36d7e7e7fe2": {
            "version": "2.50.1",
            "ppa": False,
        },
    }
    build = devcontainer.get("build", {})
    try:
        dockerfile = (root / ".devcontainer/Dockerfile").read_text(encoding="utf-8")
    except OSError:
        dockerfile = ""
    base_image = (
        "golang:1.26.4-bookworm@"
        "sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b"
    )
    docker_cli_image = (
        "docker:28.5.1-cli@"
        "sha256:9190b0613792e658a7783cf14b2d5ace5941bb68ede7276922ea36ee457d76ad"
    )
    from_lines = [
        line.strip()
        for line in dockerfile.splitlines()
        if re.match(r"^\s*FROM\s+", line, flags=re.IGNORECASE)
    ]
    if (
        features != expected_features
        or build != {"dockerfile": "Dockerfile", "context": ".."}
        or from_lines != [
            f"FROM {docker_cli_image} AS docker-cli",
            f"FROM {base_image}",
        ]
        or "COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker"
        not in dockerfile
        or "COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/"
        not in dockerfile
        or devcontainer.get("remoteUser") != "testament"
        or devcontainer.get("containerUser") != "testament"
        or devcontainer.get("privileged") is not None
        or "postCreateCommand" in devcontainer
    ):
        problems.append(
            issue(
                "VAL-READY-022",
                "devcontainer_toolchain_drift",
                ".devcontainer/devcontainer.json",
                "Devcontainer does not reproduce every pinned bootstrap tool",
                "restore .devcontainer/devcontainer.json and rebuild the container",
            )
        )

    contracts = load_json(
        root, "policy/repository-contracts.json", "VAL-READY-024", problems
    )
    entries = contracts.get("contracts", [])
    commands = contracts.get("commands", [])
    required_contracts = {
        "architecture",
        "services",
        "commands",
        "toolchain",
        "schemas",
        "conformance",
        "readiness",
    }
    contract_ids = [
        entry.get("id") for entry in entries if isinstance(entry, dict)
    ] if isinstance(entries, list) else []
    if set(contract_ids) != required_contracts or any(
        count != 1 for count in Counter(contract_ids).values()
    ):
        problems.append(
            issue(
                "VAL-READY-024",
                "incomplete_contract_registry",
                "policy/repository-contracts.json",
                "Contract registry must contain each required machine entry point once",
                "repair policy/repository-contracts.json and run make generate",
            )
        )
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        for field in ("version", "machine_path", "human_path"):
            if not entry.get(field):
                problems.append(
                    issue(
                        "VAL-READY-024",
                        "incomplete_contract_entry",
                        "policy/repository-contracts.json",
                        f"Contract {entry.get('id', '<unknown>')} lacks {field}",
                        "complete the contract entry and run make generate",
                    )
                )
        machine = entry.get("machine_path")
        human = str(entry.get("human_path", "")).split("#", 1)[0]
        if isinstance(machine, str) and not (root / machine).is_file():
            problems.append(
                issue(
                    "VAL-READY-024",
                    "unresolved_contract_path",
                    machine,
                    f"Machine contract path for {entry.get('id')} does not resolve",
                    f"restore {machine} and run make generate",
                )
            )
        if human and not (root / human).is_file():
            problems.append(
                issue(
                    "VAL-READY-024",
                    "unresolved_human_path",
                    human,
                    f"Human explanation for {entry.get('id')} does not resolve",
                    f"restore {human} and run make verify-readiness",
                )
            )

    required_commands = {
        "setup",
        "development",
        "validation",
        "schema-generation",
        "migration",
        "build",
        "release",
        "rollback",
        "doctor-recovery",
        "incident-response",
        "readiness",
        "conformance",
    }
    command_ids = [
        entry.get("id") for entry in commands if isinstance(entry, dict)
    ] if isinstance(commands, list) else []
    if (
        set(command_ids) != required_commands
        or any(count != 1 for count in Counter(command_ids).values())
    ):
        problems.append(
            issue(
                "VAL-READY-021",
                "incomplete_workflow_index",
                "policy/repository-contracts.json",
                "Each required workflow must have one documented make entry point",
                "complete the commands registry and docs/workflows.md",
            )
        )

    for relative in ("README.md", "AGENTS.md", "docs/agent-guide.md"):
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except OSError:
            continue
        required = ["make setup", "make agent-ready", "docs/workflows.md"]
        if any(marker not in text for marker in required):
            problems.append(
                issue(
                    "VAL-READY-023",
                    "incomplete_agent_guidance",
                    relative,
                    "Agent guidance lacks setup, readiness, or recovery orientation",
                    f"restore agent guidance in {relative}",
                )
            )

    for skill in SKILLS:
        relative = f".agents/skills/{skill}/SKILL.md"
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except OSError:
            continue
        required_sections = ["## Scope", "## Entry points", "## Recovery", "## Boundaries"]
        if any(section not in text for section in required_sections):
            problems.append(
                issue(
                    "VAL-READY-023",
                    "incomplete_agent_skill",
                    relative,
                    f"{skill} skill lacks required executable guidance",
                    f"complete {relative} and run make verify-readiness",
                )
            )

    index_path = root / "generated/contract-index.json"
    if index_path.is_file():
        current = load_json(
            root, "generated/contract-index.json", "VAL-READY-024", problems
        )
        try:
            expected = generated_index(root)
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            expected = {}
        if current != expected:
            problems.append(
                issue(
                    "VAL-READY-024",
                    "generated_contract_index_drift",
                    "generated/contract-index.json",
                    "Generated contract index does not match its source and contract digests",
                    "make generate",
                )
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--write-index", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.write_index:
        try:
            write_index(root)
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            problem = issue(
                "VAL-READY-024",
                "contract_index_generation_failed",
                "policy/repository-contracts.json",
                str(error),
                "repair policy/repository-contracts.json and run make generate",
            )
            print(json.dumps(problem, sort_keys=True), file=sys.stderr)
            return 1
    problems = validate(root)
    if problems:
        for problem in problems:
            print(json.dumps(problem, sort_keys=True), file=sys.stderr)
        return 1
    result = {
        "schema_version": "1.0.0",
        "status": "passed",
        "criteria": CRITERIA,
        "contract_index_sha256": digest(root / "generated/contract-index.json"),
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
