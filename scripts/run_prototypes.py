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
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


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
POSTGRES_CASES = {"postgres-storage", "decision-durability", "offline-replay"}


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


def crypto(root: Path) -> dict[str, Any]:
    source = fixture(root, "giant.json").read_bytes()
    result = subprocess.run(
        ["go", "run", "./scripts/prototype_crypto.go"],
        cwd=root,
        input=source,
        capture_output=True,
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


def key_rotation(root: Path) -> dict[str, Any]:
    value = crypto(root)
    return {
        "rewrap_changed": value["rewrap_changed"],
        "payload_ciphertext_unchanged": value["payload_unchanged"],
        "payload_ciphertext_sha256": value["payload_ciphertext_sha256"],
        "source_sha256": value["plaintext_sha256"],
        "generations": [1, 2],
        "resume_checkpoint": 1,
    }


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
SELECT json_build_object(
 'rows',(SELECT count(*) FROM prototype_storage.chunks),
 'partitions',(SELECT count(*) FROM pg_inherits WHERE inhparent='prototype_storage.chunks'::regclass),
 'ciphertext_only_columns', NOT EXISTS (
   SELECT 1 FROM information_schema.columns
   WHERE table_schema='prototype_storage' AND table_name='chunks'
     AND column_name IN ('plaintext','content','source_bytes')),
 'partition_pruning', position('chunks_2026_09' in (
   EXPLAIN (FORMAT TEXT) SELECT * FROM prototype_storage.chunks
   WHERE received_date=DATE '2026-08-21')) = 0);
DROP SCHEMA prototype_storage CASCADE;
""",
        "decision-durability": r"""
DROP SCHEMA IF EXISTS prototype_decision CASCADE;
CREATE SCHEMA prototype_decision;
CREATE TABLE prototype_decision.decisions(id text primary key);
CREATE TABLE prototype_decision.audits(id text primary key references prototype_decision.decisions);
CREATE TABLE prototype_decision.receipts(id text primary key references prototype_decision.decisions);
BEGIN;
INSERT INTO prototype_decision.decisions VALUES ('committed');
INSERT INTO prototype_decision.audits VALUES ('committed');
INSERT INTO prototype_decision.receipts VALUES ('committed');
COMMIT;
BEGIN;
INSERT INTO prototype_decision.decisions VALUES ('faulted');
INSERT INTO prototype_decision.audits VALUES ('faulted');
ROLLBACK;
SELECT json_build_object(
 'decisions',(SELECT count(*) FROM prototype_decision.decisions),
 'audits',(SELECT count(*) FROM prototype_decision.audits),
 'receipts',(SELECT count(*) FROM prototype_decision.receipts),
 'faulted_rows',(SELECT count(*) FROM prototype_decision.decisions WHERE id='faulted'));
DROP SCHEMA prototype_decision CASCADE;
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
 'late_revision_changed',(SELECT digest FROM prototype_replay.runs WHERE id=2)<>
                         (SELECT digest FROM prototype_replay.runs WHERE id=3),
 'history_preserved',(SELECT count(DISTINCT digest) FROM prototype_replay.runs)=2);
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


def sample(root: Path, case: str) -> dict[str, Any]:
    started = time.perf_counter_ns()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    observation = postgres(root, case) if case in POSTGRES_CASES else LOCAL_RUNNERS[case](root)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    rss_scale = 1 if sys.platform == "darwin" else 1024
    return {
        "elapsed_ms": round(elapsed_ms, 3),
        "process_max_rss_bytes": int(max(before, after) * rss_scale),
        "observation": observation,
    }


def accepted(case: str, samples: list[dict[str, Any]], budgets: dict[str, Any]) -> bool:
    within = all(
        item["elapsed_ms"] <= budgets["max_elapsed_ms"]
        and item["process_max_rss_bytes"] <= budgets["max_process_rss_bytes"]
        for item in samples
    )
    checks = {
        "giant-stream": lambda o: o["exact_digest"] and o["bounded_chunk_bytes"] == 65536,
        "exact-byte": lambda o: o["all_exact"] and o["classes"] >= 6,
        "compression-encryption": lambda o: o["round_trip_exact"] and o["tamper_rejected"] and o["compression_before_aead"],
        "postgres-storage": lambda o: o["rows"] == 200 and o["partitions"] == 2 and o["ciphertext_only_columns"],
        "blind-index": lambda o: o["same_scope_equality"] and o["cross_org_separation"] and o["cross_field_separation"] and o["rotation_changes_token"],
        "key-rotation": lambda o: o["rewrap_changed"] and o["payload_ciphertext_unchanged"],
        "decision-durability": lambda o: o["decisions"] == o["audits"] == o["receipts"] == 1 and o["faulted_rows"] == 0,
        "analyzer-isolation": analyzer_isolation_accepted,
        "offline-replay": lambda o: o["runs"] == 3 and o["recorded_replay_equal"] and o["late_revision_changed"] and o["history_preserved"],
    }
    return within and all(checks[case](item["observation"]) for item in samples)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--plan-commit", required=True)
    parser.add_argument("--postgres", action="store_true")
    parser.add_argument("--case", action="append", choices=sorted(RESULT_PATHS))
    args = parser.parse_args()
    root = args.root.resolve()
    plan = json.loads(
        (root / "docs/research/benchmarks/precommit.json").read_text(encoding="utf-8")
    )
    selected = set(args.case or RESULT_PATHS)
    if not args.postgres:
        selected -= POSTGRES_CASES
    environment = machine_environment(root)
    plan_digest = canonical_digest(plan)
    for case_plan in plan["cases"]:
        case = case_plan["id"]
        if case not in selected:
            continue
        samples = [
            sample(root, case) for _ in range(case_plan["sample_count"])
        ]
        conclusion = "pass" if accepted(case, samples, case_plan["budgets"]) else "fail"
        result = {
            "schema_version": "1.0.0",
            "feature_id": "storage-analysis-prototypes-and-evaluation-plan",
            "validation_id": "VAL-READY-014",
            "prototype_id": case,
            "benchmark_id": f"{case}-benchmark",
            "version": "1.0.0",
            "plan_commit": args.plan_commit,
            "plan_sha256": plan_digest,
            "environment": environment,
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
        }
        if case in POSTGRES_CASES:
            result["environment"]["postgres"] = {
                "major": 17,
                "port": 5440,
                "service": "postgres",
                "lifecycle_manifest": (
                    "/Users/enoreyes/.factory/missions/"
                    "81566df0-610b-4ff7-b16d-2a10ad666e64/services.yaml"
                ),
                "healthcheck": "pg_isready -p 5440",
            }
        path = root / RESULT_PATHS[case]
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
        print(json.dumps({"case": case, "conclusion": conclusion, "path": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
