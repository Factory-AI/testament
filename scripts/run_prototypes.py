#!/usr/bin/env python3
"""Run disposable Milestone 1 prototypes and preserve raw JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

try:
    import prototype_decision_durability
    from prototype_resources import (
        AccountingError,
        ServicesManifest,
        observe_local_process,
        observe_postgres_process,
        validate_accounting,
        valid_resource_sample,
    )
except ModuleNotFoundError:
    from scripts import prototype_decision_durability
    from scripts.prototype_resources import (
        AccountingError,
        ServicesManifest,
        observe_local_process,
        observe_postgres_process,
        validate_accounting,
        valid_resource_sample,
    )


RESULT_PATHS = {
    "giant-stream": "docs/research/benchmarks/giant-stream.json",
    "exact-byte": "docs/research/benchmarks/exact-byte.json",
    "compression-encryption": "docs/research/benchmarks/compression-encryption.json",
    "postgres-storage": "docs/research/benchmarks/postgres-storage.json",
    "blind-index": "docs/research/benchmarks/blind-index.json",
    "key-rotation": "docs/research/benchmarks/key-rotation.json",
    "decision-durability": "docs/research/benchmarks/decision-durability.json",
    "analyzer-isolation": "docs/research/benchmarks/analyzer-isolation.json",
    "offline-replay": "docs/research/benchmarks/offline-replay.json",
}
SUCCESSOR_PLAN_COMMIT = "0f3dce5b9418a50eb031ec3fd561282462533bd3"
SUCCESSOR_PLAN_PATH = "docs/research/benchmarks/precommit-v2.json"
POSTGRES_CASES = {"postgres-storage", "decision-durability", "offline-replay"}
RESULT_PLAN_FIELDS = (
    "inputs",
    "sample_count",
    "budgets",
    "tolerances",
    "comparison_method",
    "acceptance_rule",
    "limitations",
    "tolerance_history",
)


def clean_clone_evidence(root: Path) -> dict[str, Any]:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    alternates = root / ".git" / "objects" / "info" / "alternates"
    evidence = {
        "worktree_clean_before_measurement": not status,
        "independent_object_store": not alternates.exists(),
        "complete_history": shallow == "false",
    }
    if not all(evidence.values()):
        raise RuntimeError(
            "clean-clone reporting requires a clean worktree, an independent "
            "object store, and complete Git history"
        )
    return evidence


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def command_version(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return (result.stdout or result.stderr).splitlines()[0]


def machine_environment(root: Path) -> dict[str, Any]:
    memory = subprocess.run(
        ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=False
    )
    return {
        "os": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": int(memory.stdout.strip()) if memory.returncode == 0 else None,
        "python": platform.python_version(),
        "go": command_version(["go", "version"]),
        "docker": command_version(["docker", "--version"]),
        "tested_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "machine_class": "developer-workstation-12cpu-18gib",
    }


def require_committed_successor(root: Path) -> None:
    ancestor = subprocess.run(
        [
            "git",
            "merge-base",
            "--is-ancestor",
            SUCCESSOR_PLAN_COMMIT,
            "HEAD",
        ],
        cwd=root,
        capture_output=True,
        check=False,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if ancestor.returncode != 0 or status:
        raise RuntimeError(
            "version 2 measurement requires a clean tested implementation "
            "commit descending from the successor plan commit"
        )


def fixture(root: Path, name: str) -> Path:
    path = root / "fixtures" / "research-corpus" / name
    if not path.is_file():
        raise RuntimeError(f"missing fixture: {path}")
    return path


def giant_stream(root: Path) -> dict[str, Any]:
    path = fixture(root, "giant.json")
    digest = hashlib.sha256()
    total = 0
    chunks = 0
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            digest.update(block)
            total += len(block)
            chunks += 1
    return {
        "bytes": total,
        "chunks": chunks,
        "sha256": digest.hexdigest(),
        "bounded_chunk_bytes": 64 * 1024,
        "exact_digest": digest.hexdigest()
        == hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def exact_byte(root: Path) -> dict[str, Any]:
    names = [
        "malformed.json",
        "malformed.jsonl",
        "provider-openai-stream-tool.jsonl",
    ]
    values = [fixture(root, name).read_bytes() for name in names]
    values.extend([b"", b"\x00\xff\r\ninvalid\x80text", bytes(range(256))])
    with tempfile.TemporaryDirectory() as directory:
        for index, value in enumerate(values):
            path = Path(directory) / str(index)
            path.write_bytes(value)
            if path.read_bytes() != value:
                return {"classes": len(values), "all_exact": False}
    return {
        "classes": len(values),
        "all_exact": True,
        "aggregate_sha256": canonical_digest(
            [hashlib.sha256(value).hexdigest() for value in values]
        ),
    }


def crypto(root: Path, mutation: str | None = None) -> dict[str, Any]:
    source = fixture(root, "giant.json").read_bytes()
    environment = os.environ.copy()
    if mutation:
        environment["TESTAMENT_KEY_ROTATION_MUTATION"] = mutation
    result = subprocess.run(
        ["go", "run", "./scripts/prototype_crypto.go"],
        cwd=root,
        input=source,
        capture_output=True,
        env=environment,
        check=True,
    )
    return json.loads(result.stdout)


def blind_index(_: Path) -> dict[str, Any]:
    value = b"synthetic-equality-value"

    def token(org: str, field: str, generation: int) -> str:
        key = hashlib.sha256(
            f"synthetic:{org}:{field}:{generation}".encode()
        ).digest()
        normalized = value.strip().lower()
        return hmac.new(key, normalized, hashlib.sha256).hexdigest()

    same = token("org-a", "actor", 1) == token("org-a", "actor", 1)
    cross_org = token("org-a", "actor", 1) != token("org-b", "actor", 1)
    cross_field = token("org-a", "actor", 1) != token("org-a", "target", 1)
    rotation = token("org-a", "actor", 1) != token("org-a", "actor", 2)
    return {
        "same_scope_equality": same,
        "cross_org_separation": cross_org,
        "cross_field_separation": cross_field,
        "rotation_changes_token": rotation,
        "token_bytes": 32,
        "documented_leakage": "equality and frequency within one org/field/generation",
    }


def key_rotation(
    root: Path,
    mutation: str | None = None,
) -> dict[str, Any]:
    value = crypto(root, mutation=mutation)
    observation = {
        "rewrap_changed": value["rewrap_changed"],
        "payload_ciphertext_unchanged": value["payload_unchanged"],
        "payload_ciphertext_sha256": value["payload_ciphertext_sha256"],
        "pre_rewrap_payload_capture": value["pre_rewrap_payload_capture"],
        "post_rewrap_payload_capture": value["post_rewrap_payload_capture"],
        "old_wrapped_dek": value["old_wrapped_dek"],
        "new_wrapped_dek": value["new_wrapped_dek"],
        "operation_sequence": value["operation_sequence"],
        "source_sha256": value["plaintext_sha256"],
        "generations": value["generations"],
        "resume_checkpoint": value["resume_checkpoint"],
    }
    observation["acceptance_recomputed"] = key_rotation_accepted(observation)
    return observation


def key_rotation_accepted(observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    before = observation.get("pre_rewrap_payload_capture")
    after = observation.get("post_rewrap_payload_capture")
    old_wrap = observation.get("old_wrapped_dek")
    new_wrap = observation.get("new_wrapped_dek")
    if not all(
        isinstance(value, dict)
        for value in (before, after, old_wrap, new_wrap)
    ):
        return False
    payload_equal = (
        before.get("sha256") == after.get("sha256")
        and before.get("byte_count") == after.get("byte_count")
    )
    wrapped_deks_differ = old_wrap.get("sha256") != new_wrap.get("sha256")
    independently_captured = (
        before.get("capture_id") != after.get("capture_id")
        and before.get("method")
        == after.get("method")
        == "os.ReadFile persisted payload_ciphertext.bin"
        and before.get("phase") == "immediately-before-rewrap"
        and after.get("phase") == "after-new-wrapped-dek-and-checkpoint"
        and before.get("read_ordinal") == 1
        and after.get("read_ordinal") == 2
    )
    return (
        independently_captured
        and observation.get("operation_sequence")
        == [
            "pre_payload_capture",
            "new_wrapped_dek_persisted",
            "checkpoint_persisted",
            "post_payload_capture",
        ]
        and isinstance(before.get("byte_count"), int)
        and before["byte_count"] > 0
        and isinstance(before.get("sha256"), str)
        and len(before["sha256"]) == 64
        and isinstance(old_wrap.get("byte_count"), int)
        and old_wrap["byte_count"] > 0
        and isinstance(new_wrap.get("byte_count"), int)
        and new_wrap["byte_count"] > 0
        and isinstance(old_wrap.get("sha256"), str)
        and len(old_wrap["sha256"]) == 64
        and isinstance(new_wrap.get("sha256"), str)
        and len(new_wrap["sha256"]) == 64
        and old_wrap.get("persisted_path")
        == "wrapped_dek.generation-1.bin"
        and new_wrap.get("persisted_path")
        == "wrapped_dek.generation-2.bin"
        and old_wrap.get("generation") == 1
        and new_wrap.get("generation") == 2
        and observation.get("generations") == [1, 2]
        and observation.get("resume_checkpoint") == 1
        and observation.get("payload_ciphertext_sha256")
        == before.get("sha256")
        and observation.get("payload_ciphertext_unchanged")
        is payload_equal
        and observation.get("rewrap_changed") is wrapped_deks_differ
        and payload_equal
        and wrapped_deks_differ
    )


def analyzer_isolation(_: Path) -> dict[str, Any]:
    cpu_limit = 1
    address_space_limit = 512 << 30 if sys.platform == "darwin" else 512 << 20
    file_descriptor_limit = 16
    output_limit = 4096
    deadline_limit = 2
    allowed_environment = {"PATH", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    script = (
        "import json,os,resource;"
        "print(json.dumps({'env':sorted(os.environ),'cwd':os.getcwd(),"
        "'cpu':resource.getrlimit(resource.RLIMIT_CPU)[0],"
        "'as_limit':resource.getrlimit(resource.RLIMIT_AS)[0],"
        "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE)[0],"
        "'fsize':resource.getrlimit(resource.RLIMIT_FSIZE)[0]}))"
    )
    output_probe_script = (
        "import os;"
        f"block=b'x'*{output_limit};"
        "[os.write(1,block) for _ in range(2)]"
    )
    deadline_probe_script = f"import time;time.sleep({deadline_limit + 1})"

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (file_descriptor_limit, file_descriptor_limit),
        )
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(
                resource.RLIMIT_AS, (address_space_limit, address_space_limit)
            )

    with (
        tempfile.TemporaryDirectory() as directory,
        tempfile.TemporaryFile() as output,
        tempfile.TemporaryFile() as output_probe,
    ):
        subprocess_options = {
            "cwd": directory,
            "env": {"PATH": "/usr/bin:/bin"},
            "timeout": deadline_limit,
            "preexec_fn": limits,
        }
        subprocess.run(
            [sys.executable, "-c", script],
            stdout=output,
            stderr=output,
            check=True,
            **subprocess_options,
        )
        output_probe_result = subprocess.run(
            [sys.executable, "-c", output_probe_script],
            stdout=output_probe,
            stderr=subprocess.DEVNULL,
            check=False,
            **subprocess_options,
        )
        deadline_limit_enforced = False
        try:
            subprocess.run(
                [sys.executable, "-c", deadline_probe_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                **subprocess_options,
            )
        except subprocess.TimeoutExpired:
            deadline_limit_enforced = True
        output.seek(0)
        encoded_output = output.read(output_limit + 1)
        output_probe.seek(0)
        output_probe_bytes = len(output_probe.read(output_limit + 1))
    child = json.loads(encoded_output)
    unexpected_environment = sorted(set(child["env"]) - allowed_environment)
    return {
        "sanitized_environment": (
            "PATH" in child["env"] and not unexpected_environment
        ),
        "visible_environment_variables": child["env"],
        "allowed_environment_variables": sorted(allowed_environment),
        "unexpected_environment_variables": unexpected_environment,
        "isolated_working_directory": (
            os.path.realpath(child["cwd"]) == os.path.realpath(directory)
        ),
        "cpu_limit_seconds": child["cpu"],
        "file_descriptor_limit": child["nofile"],
        "address_space_limit_bytes": child["as_limit"],
        "address_space_limit_enforced": child["as_limit"] == address_space_limit,
        "deadline_seconds": deadline_limit,
        "deadline_limit_enforced": deadline_limit_enforced,
        "output_bytes": len(encoded_output),
        "output_limit_bytes": output_limit,
        "output_probe_bytes": output_probe_bytes,
        "output_limit_enforced": (
            output_probe_result.returncode != 0
            and output_probe_bytes <= child["fsize"] == output_limit
        ),
        "network_denial_proven": False,
        "hostile_multi_tenant_isolation_proven": False,
        "conclusion": (
            "POSIX subprocess limits bound CPU, address space, descriptors, "
            "environment, working directory, time, and output, but do not "
            "prove network denial; plain subprocess isolation is rejected "
            "as a hostile multi-tenant isolation boundary."
        ),
    }


def postgres(root: Path, case: str) -> dict[str, Any]:
    sql_by_case = {
        "postgres-storage": r"""
DROP SCHEMA IF EXISTS prototype_storage CASCADE;
CREATE SCHEMA prototype_storage;
CREATE TABLE prototype_storage.chunks(
  org_id text NOT NULL, received_date date NOT NULL, artifact_id int NOT NULL,
  ordinal int NOT NULL, ciphertext bytea NOT NULL
) PARTITION BY RANGE(received_date);
CREATE TABLE prototype_storage.chunks_2026_08 PARTITION OF prototype_storage.chunks
  FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE prototype_storage.chunks_2026_09 PARTITION OF prototype_storage.chunks
  FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
INSERT INTO prototype_storage.chunks
SELECT 'org-synthetic', DATE '2026-08-21', n, 0,
       decode(repeat(md5(n::text), 32), 'hex') FROM generate_series(1,200) n;
CREATE TEMP TABLE prototype_storage_plan(
  ordinal bigint GENERATED ALWAYS AS IDENTITY, line text NOT NULL
);
DO $body$
DECLARE plan_line text;
BEGIN
  FOR plan_line IN EXECUTE
    $query$EXPLAIN (COSTS OFF) SELECT * FROM prototype_storage.chunks
      WHERE received_date=DATE '2026-08-21'$query$
  LOOP
    INSERT INTO prototype_storage_plan(line) VALUES (plan_line);
  END LOOP;
END
$body$;
SELECT json_build_object(
 'rows',(SELECT count(*) FROM prototype_storage.chunks),
 'partitions',(SELECT count(*) FROM pg_inherits WHERE inhparent='prototype_storage.chunks'::regclass),
 'ciphertext_nonempty_rows',(SELECT count(*) FROM prototype_storage.chunks WHERE octet_length(ciphertext)>0),
 'content_column','ciphertext',
 'content_column_type',(SELECT data_type FROM information_schema.columns
   WHERE table_schema='prototype_storage' AND table_name='chunks' AND column_name='ciphertext'),
 'forbidden_plaintext_columns',(SELECT count(*) FROM information_schema.columns
   WHERE table_schema='prototype_storage' AND table_name='chunks'
     AND column_name IN ('plaintext','content','source_bytes')),
 'ciphertext_only_columns', NOT EXISTS (
   SELECT 1 FROM information_schema.columns
   WHERE table_schema='prototype_storage' AND table_name='chunks'
     AND column_name IN ('plaintext','content','source_bytes')),
 'partition_pruning',
   EXISTS (SELECT 1 FROM prototype_storage_plan WHERE line LIKE '%chunks_2026_08%')
   AND NOT EXISTS (SELECT 1 FROM prototype_storage_plan WHERE line LIKE '%chunks_2026_09%'),
 'executed_partition','chunks_2026_08',
 'pruned_partition','chunks_2026_09',
 'explain_lines',(SELECT json_agg(line ORDER BY ordinal) FROM prototype_storage_plan));
DROP SCHEMA prototype_storage CASCADE;
""",
        "offline-replay": r"""
DROP SCHEMA IF EXISTS prototype_replay CASCADE;
CREATE SCHEMA prototype_replay;
CREATE TABLE prototype_replay.events(id int primary key, watermark int, body text);
CREATE TABLE prototype_replay.runs(id int primary key, watermark int, digest text, supersedes int);
INSERT INTO prototype_replay.events VALUES (1,1,'a'),(2,2,'b'),(3,3,'c');
INSERT INTO prototype_replay.runs
SELECT 1,3,md5(string_agg(id||':'||body,',' ORDER BY id)),NULL
FROM prototype_replay.events WHERE watermark <= 3;
INSERT INTO prototype_replay.runs
SELECT 2,3,md5(string_agg(id||':'||body,',' ORDER BY id)),1
FROM prototype_replay.events WHERE watermark <= 3;
INSERT INTO prototype_replay.events VALUES (4,2,'late');
INSERT INTO prototype_replay.runs
SELECT 3,3,md5(string_agg(id||':'||body,',' ORDER BY id)),2
FROM prototype_replay.events WHERE watermark <= 3;
SELECT json_build_object(
 'runs',(SELECT count(*) FROM prototype_replay.runs),
 'recorded_replay_equal',(SELECT digest FROM prototype_replay.runs WHERE id=1)=
                         (SELECT digest FROM prototype_replay.runs WHERE id=2),
 'pinned_replay_digests',json_build_array(
   (SELECT digest FROM prototype_replay.runs WHERE id=1),
   (SELECT digest FROM prototype_replay.runs WHERE id=2)),
 'late_revision_changed',(SELECT digest FROM prototype_replay.runs WHERE id=2)<>
                         (SELECT digest FROM prototype_replay.runs WHERE id=3),
 'late_revision',(SELECT json_build_object(
   'id',id,'watermark',watermark,'digest',digest,'supersedes',supersedes,
   'includes_late_event',EXISTS(
     SELECT 1 FROM prototype_replay.events WHERE id=4 AND watermark<=r.watermark))
   FROM prototype_replay.runs r WHERE id=3),
 'run_history',(SELECT json_agg(json_build_object(
   'id',id,'watermark',watermark,'digest',digest,'supersedes',supersedes)
   ORDER BY id) FROM prototype_replay.runs),
 'history_preserved',(
   (SELECT count(*) FROM prototype_replay.runs)=3
   AND (SELECT count(DISTINCT digest) FROM prototype_replay.runs)=2
   AND EXISTS(SELECT 1 FROM prototype_replay.runs WHERE id=1)
   AND EXISTS(SELECT 1 FROM prototype_replay.runs WHERE id=2)));
DROP SCHEMA prototype_replay CASCADE;
""",
    }
    version = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "postgres", "psql",
            "-U", "testament", "-d", "testament", "-p", "5440", "-Atqc",
            "SHOW server_version;",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "postgres", "psql",
            "-U", "testament", "-d", "testament", "-p", "5440",
            "-v", "ON_ERROR_STOP=1", "-Atq",
        ],
        cwd=root,
        input=sql_by_case[case],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        raise RuntimeError(f"unexpected PostgreSQL output: {result.stdout}")
    value = json.loads(lines[0])
    value["postgres_version"] = version
    value["port"] = 5440
    return value


LOCAL_RUNNERS: dict[str, Callable[[Path], dict[str, Any]]] = {
    "giant-stream": giant_stream,
    "exact-byte": exact_byte,
    "compression-encryption": crypto,
    "blind-index": blind_index,
    "key-rotation": key_rotation,
    "analyzer-isolation": analyzer_isolation,
}


def analyzer_isolation_accepted(observation: dict[str, Any]) -> bool:
    return (
        observation["sanitized_environment"]
        and not observation["unexpected_environment_variables"]
        and observation["isolated_working_directory"]
        and observation["cpu_limit_seconds"] == 1
        and observation["address_space_limit_enforced"]
        and 0 < observation["address_space_limit_bytes"] < 1 << 63
        and observation["file_descriptor_limit"] == 16
        and observation["output_limit_enforced"]
        and observation["output_limit_bytes"] == 4096
        and observation["deadline_limit_enforced"]
        and observation["deadline_seconds"] == 2
        and not observation["network_denial_proven"]
        and not observation["hostile_multi_tenant_isolation_proven"]
    )


def worker_observation(root: Path, case: str) -> dict[str, Any]:
    if case == "decision-durability":
        return prototype_decision_durability.run(root)
    return postgres(root, case) if case in POSTGRES_CASES else LOCAL_RUNNERS[case](root)


def decode_worker_observation(result_stdout: str, result_stderr: str) -> dict[str, Any]:
    lines = [line for line in result_stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return {
            "worker_completed": False,
            "worker_error": result_stderr.strip() or "worker emitted invalid output",
        }
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError:
        return {
            "worker_completed": False,
            "worker_error": "worker emitted non-JSON output",
        }
    if not isinstance(value, dict):
        return {
            "worker_completed": False,
            "worker_error": "worker observation was not an object",
        }
    return value


def sample(
    root: Path,
    case: str,
    budgets: dict[str, Any],
    services_manifest: ServicesManifest | None,
) -> dict[str, Any]:
    started = time.perf_counter_ns()
    command = [
        sys.executable,
        str(root / "scripts" / "run_prototypes.py"),
        "--root",
        str(root),
        "--worker-case",
        case,
    ]
    budget_bytes = budgets["max_process_rss_bytes"]
    if case in POSTGRES_CASES:
        if services_manifest is None:
            raise AccountingError(
                "PostgreSQL samples require --services-manifest services.yaml"
            )
        result = observe_postgres_process(
            command,
            cwd=root,
            manifest=services_manifest,
            budget_bytes=budget_bytes,
            hard_limit_bytes=budget_bytes,
            timeout_ms=budgets["max_elapsed_ms"],
        )
    else:
        result = observe_local_process(
            command,
            cwd=root,
            budget_bytes=budget_bytes,
            hard_limit_bytes=budget_bytes,
            timeout_ms=budgets["max_elapsed_ms"],
        )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    validate_accounting(result.accounting)
    observation = decode_worker_observation(result.stdout, result.stderr)
    observation["worker_completed"] = (
        result.returncode == 0 and not result.limit_exceeded
    )
    if result.stderr.strip():
        observation["worker_diagnostic"] = result.stderr.strip()
    return {
        "elapsed_ms": round(elapsed_ms, 3),
        "resource_accounting": result.accounting,
        "observation": observation,
    }


def accepted(case: str, samples: list[dict[str, Any]], budgets: dict[str, Any]) -> bool:
    expected_scope = (
        "postgres_container_cgroup"
        if case in POSTGRES_CASES
        else "worker_descendant_tree"
    )
    within = all(
        valid_resource_sample(item, budgets, expected_scope)
        for item in samples
    )
    checks = {
        "giant-stream": lambda o: o["exact_digest"] and o["bounded_chunk_bytes"] == 65536,
        "exact-byte": lambda o: o["all_exact"] and o["classes"] >= 6,
        "compression-encryption": lambda o: o["round_trip_exact"] and o["tamper_rejected"] and o["compression_before_aead"],
        "postgres-storage": lambda o: (
            o["rows"] == 200
            and o["partitions"] == 2
            and o["ciphertext_nonempty_rows"] == 200
            and o["content_column_type"] == "bytea"
            and o["forbidden_plaintext_columns"] == 0
            and o["ciphertext_only_columns"]
            and o["partition_pruning"]
        ),
        "blind-index": lambda o: o["same_scope_equality"] and o["cross_org_separation"] and o["cross_field_separation"] and o["rotation_changes_token"],
        "key-rotation": key_rotation_accepted,
        "decision-durability": prototype_decision_durability.accepted_observation,
        "analyzer-isolation": analyzer_isolation_accepted,
        "offline-replay": lambda o: (
            o["runs"] == 3
            and o["recorded_replay_equal"]
            and len(set(o["pinned_replay_digests"])) == 1
            and o["late_revision_changed"]
            and o["late_revision"]["supersedes"] == 2
            and o["late_revision"]["includes_late_event"]
            and len(o["run_history"]) == 3
            and o["history_preserved"]
        ),
    }
    return within and all(checks[case](item["observation"]) for item in samples)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--plan-commit")
    parser.add_argument("--postgres", action="store_true")
    parser.add_argument("--case", action="append", choices=sorted(RESULT_PATHS))
    parser.add_argument(
        "--services-manifest",
        type=Path,
        help="Mission services.yaml; required when PostgreSQL cases are selected.",
    )
    parser.add_argument(
        "--worker-case",
        choices=sorted(RESULT_PATHS),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Required version 2 result directory outside version 1 paths.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Write a clean-clone comparison report after all nine cases run.",
    )
    parser.add_argument(
        "--clean-clone",
        action="store_true",
        help="Attest that the root is a newly created Git clone.",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if args.worker_case:
        print(json.dumps(worker_observation(root, args.worker_case)))
        return 0
    if args.plan_commit != SUCCESSOR_PLAN_COMMIT:
        parser.error(
            f"--plan-commit must be committed successor {SUCCESSOR_PLAN_COMMIT}"
        )
    if not args.output_dir:
        parser.error(
            "--output-dir is required; version 2 runs may not overwrite "
            "version 1 raw results"
        )
    require_committed_successor(root)
    if args.report and not args.clean_clone:
        parser.error("--report requires --clean-clone")
    clone_evidence = clean_clone_evidence(root) if args.clean_clone else None
    plan = json.loads(
        (root / SUCCESSOR_PLAN_PATH).read_text(encoding="utf-8")
    )
    selected = set(args.case or RESULT_PATHS)
    if not args.postgres:
        selected -= POSTGRES_CASES
    if selected & POSTGRES_CASES and args.services_manifest is None:
        parser.error("PostgreSQL samples require --services-manifest services.yaml")
    services_manifest = (
        ServicesManifest.from_path(args.services_manifest)
        if args.services_manifest
        else None
    )
    environment = machine_environment(root)
    plan_digest = canonical_digest(plan)
    generated: dict[str, dict[str, Any]] = {}
    for case_plan in plan["cases"]:
        case = case_plan["id"]
        if case not in selected:
            continue
        samples = [
            sample(root, case, case_plan["budgets"], services_manifest)
            for _ in range(case_plan["sample_count"])
        ]
        conclusion = "pass" if accepted(case, samples, case_plan["budgets"]) else "fail"
        result_environment = dict(environment)
        v1_result_path = RESULT_PATHS[case]
        result = {
            "schema_version": "1.0.0",
            "feature_id": "prototype-v2-clean-clone-reconciliation",
            "validation_id": "VAL-READY-014",
            "prototype_id": case,
            "benchmark_id": f"{case}-benchmark",
            "version": "2.0.0",
            "plan_commit": args.plan_commit,
            "plan_sha256": plan_digest,
            "environment": result_environment,
            "inputs": case_plan["inputs"],
            "sample_count": case_plan["sample_count"],
            "budgets": case_plan["budgets"],
            "tolerances": case_plan["tolerances"],
            "comparison_method": case_plan["comparison_method"],
            "acceptance_rule": case_plan["acceptance_rule"],
            "samples": samples,
            "conclusion": conclusion,
            "limitations": case_plan["limitations"],
            "tolerance_history": plan["tolerance_history"],
            "supersedes": {
                "path": v1_result_path,
                "version": "1.0.0",
                "sha256": hashlib.sha256(
                    (root / v1_result_path).read_bytes()
                ).hexdigest(),
                "status": "superseded-evidence",
                "preserved": True,
            },
        }
        if case in POSTGRES_CASES:
            result_environment["postgres"] = {
                "major": 17,
                "port": 5440,
                "service": "postgres",
                "lifecycle_manifest": "services.yaml",
                "healthcheck": "pg_isready -p 5440",
                "resource_source": "Docker container statistics backed by the postgres container cgroup",
            }
        path = args.output_dir / f"{case}.json"
        if path.resolve() == (root / RESULT_PATHS[case]).resolve():
            raise RuntimeError("version 2 result path collides with version 1")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
        generated[case] = result
        print(json.dumps({"case": case, "conclusion": conclusion, "path": str(path)}))
    if args.report:
        source_commit = environment["tested_commit"]
        comparisons = []
        for case in sorted(RESULT_PATHS):
            if case not in generated:
                raise RuntimeError("A reproduction report requires all nine cases")
            rerun = generated[case]
            case_plan = next(
                row for row in plan["cases"] if row["id"] == case
            )
            sample_count_matches = (
                rerun.get("sample_count") == len(rerun.get("samples", []))
            )
            plan_fields_match = all(
                rerun.get(field)
                == (
                    plan.get("tolerance_history")
                    if field == "tolerance_history"
                    else case_plan.get(field)
                )
                for field in RESULT_PLAN_FIELDS
            )
            comparisons.append(
                {
                    "prototype_id": case,
                    "result_path": f"docs/research/benchmarks/v2/{case}.json",
                    "supersedes_result_path": RESULT_PATHS[case],
                    "raw_result": rerun,
                    "comparison": {
                        "method": "Recompute version 2 plan fields, declared sample count, workload acceptance, and resource accounting; timing and randomized cryptographic observations are not required to be byte-identical.",
                        "rerun_conclusion": rerun.get("conclusion"),
                        "sample_count_matches": sample_count_matches,
                        "plan_fields_match": plan_fields_match,
                        "matches": (
                            rerun.get("conclusion") == "pass"
                            and sample_count_matches
                            and plan_fields_match
                        ),
                    },
                }
            )
        report = {
            "schema_version": "1.0.0",
            "feature_id": "prototype-v2-clean-clone-reconciliation",
            "validation_id": "VAL-READY-014",
            "status": (
                "pass"
                if all(row["comparison"]["matches"] for row in comparisons)
                else "fail"
            ),
            "clean_clone": args.clean_clone,
            "clean_clone_evidence": clone_evidence,
            "clone_method": "git clone --no-local from the candidate object database into an empty temporary directory",
            "source_commit": source_commit,
            "plan_commit": args.plan_commit,
            "plan_sha256": plan_digest,
            "sample_count": sum(
                result["sample_count"] for result in generated.values()
            ),
            "results": comparisons,
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"report": str(args.report), "status": report["status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
