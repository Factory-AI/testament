#!/usr/bin/env python3
"""Exercise PostgreSQL automatic rollback after exact backend termination."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any


FAULT_TRANSACTION_SQL = r"""
SET application_name TO :'session_id';
BEGIN;
INSERT INTO prototype_decision.decisions VALUES (:'fault_id');
INSERT INTO prototype_decision.audits VALUES (:'fault_id');
SELECT 'TESTAMENT_FAULT_READY:' || pg_backend_pid() || ':' || :'session_id';
SELECT pg_sleep(300);
"""

SETUP_SQL = r"""
DROP SCHEMA IF EXISTS prototype_decision CASCADE;
CREATE SCHEMA prototype_decision;
CREATE TABLE prototype_decision.decisions(id text primary key);
CREATE TABLE prototype_decision.audits(
  id text primary key references prototype_decision.decisions
);
CREATE TABLE prototype_decision.receipts(
  id text primary key references prototype_decision.decisions
);
BEGIN;
INSERT INTO prototype_decision.decisions VALUES ('committed');
INSERT INTO prototype_decision.audits VALUES ('committed');
INSERT INTO prototype_decision.receipts VALUES ('committed');
COMMIT;
"""

CLEANUP_SQL = "DROP SCHEMA IF EXISTS prototype_decision CASCADE;\n"


def _psql_command(*extra: str) -> list[str]:
    return [
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
        "-v",
        "ON_ERROR_STOP=1",
        *extra,
    ]


def _run_sql(root: Path, sql: str, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _psql_command(*extra, "-Atq"),
        cwd=root,
        input=sql,
        capture_output=True,
        text=True,
        check=True,
    )


def _one_json(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    rows = [line for line in result.stdout.splitlines() if line.startswith("{")]
    if len(rows) != 1:
        raise RuntimeError(f"expected one PostgreSQL JSON row: {result.stdout!r}")
    value = json.loads(rows[0])
    if not isinstance(value, dict):
        raise RuntimeError("PostgreSQL observation must be an object")
    return value


def _wait_for_readiness(
    process: subprocess.Popen[str],
    *,
    timeout_seconds: float,
) -> str:
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            events = selector.select(timeout=min(0.1, deadline - time.monotonic()))
            for _, _ in events:
                line = process.stdout.readline().strip()
                if line.startswith("TESTAMENT_FAULT_READY:"):
                    return line
    finally:
        selector.close()
    raise RuntimeError("fault client did not emit its in-transaction readiness marker")


def _stop_owned_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def accepted_observation(observation: Any) -> bool:
    if not isinstance(observation, dict):
        return False
    marker = observation.get("readiness_marker")
    session_id = observation.get("fault_session_id")
    backend_pid = observation.get("fault_backend_pid")
    return (
        observation.get("fault_type") == "postgresql-backend-termination"
        and isinstance(session_id, str)
        and session_id.startswith("testament-fault-")
        and isinstance(backend_pid, int)
        and backend_pid > 0
        and isinstance(marker, str)
        and marker == f"TESTAMENT_FAULT_READY:{backend_pid}:{session_id}"
        and observation.get("readiness_observed") is True
        and observation.get("transaction_active_before_injection") is True
        and observation.get("backend_identity_matched") is True
        and observation.get("termination_acknowledged") is True
        and observation.get("explicit_rollback_issued") is False
        and observation.get("client_connection_lost") is True
        and isinstance(observation.get("fault_client_exit_code"), int)
        and observation["fault_client_exit_code"] != 0
        and observation.get("backend_disappeared") is True
        and observation.get("verification_connection_fresh") is True
        and observation.get("automatic_rollback_verified") is True
        and observation.get("decisions") == 1
        and observation.get("audits") == 1
        and observation.get("receipts") == 1
        and observation.get("faulted_decisions") == 0
        and observation.get("faulted_audits") == 0
        and observation.get("faulted_receipts") == 0
        and observation.get("faulted_rows") == 0
        and observation.get("orphan_audits") == 0
        and observation.get("orphan_receipts") == 0
        and str(observation.get("postgres_version", "")).startswith("17.")
        and observation.get("port") == 5440
    )


def run(root: Path) -> dict[str, Any]:
    session_id = f"testament-fault-{uuid.uuid4().hex[:16]}"
    fault_id = f"faulted-{uuid.uuid4().hex[:16]}"
    fault_process: subprocess.Popen[str] | None = None
    _run_sql(root, SETUP_SQL)
    try:
        version = _run_sql(root, "SHOW server_version;").stdout.strip()
        fault_process = subprocess.Popen(
            _psql_command(
                "-v",
                f"session_id={session_id}",
                "-v",
                f"fault_id={fault_id}",
                "-Atq",
            ),
            cwd=root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        assert fault_process.stdin is not None
        fault_process.stdin.write(FAULT_TRANSACTION_SQL)
        fault_process.stdin.close()
        fault_process.stdin = None
        marker = _wait_for_readiness(fault_process, timeout_seconds=5)
        marker_parts = marker.split(":", 2)
        if len(marker_parts) != 3:
            raise RuntimeError(f"invalid readiness marker: {marker!r}")
        backend_pid = int(marker_parts[1])
        if marker_parts[2] != session_id:
            raise RuntimeError("fault readiness marker session did not match")

        preinject = _one_json(
            _run_sql(
                root,
                f"""
SELECT json_build_object(
  'backend_pid', pid,
  'application_name', application_name,
  'transaction_active', xact_start IS NOT NULL,
  'state', state,
  'wait_event_type', wait_event_type,
  'wait_event', wait_event)
FROM pg_stat_activity
WHERE pid = {backend_pid};
""",
            )
        )
        backend_identity_matched = (
            preinject.get("backend_pid") == backend_pid
            and preinject.get("application_name") == session_id
        )
        transaction_active = (
            preinject.get("transaction_active") is True
            and preinject.get("state") == "active"
            and preinject.get("wait_event_type") == "Timeout"
            and preinject.get("wait_event") == "PgSleep"
        )

        termination = _one_json(
            _run_sql(
                root,
                f"""
SELECT json_build_object(
  'control_backend_pid', pg_backend_pid(),
  'target_backend_pid', {backend_pid},
  'acknowledged', pg_terminate_backend({backend_pid}))
WHERE EXISTS (
  SELECT 1 FROM pg_stat_activity
  WHERE pid = {backend_pid}
    AND application_name = '{session_id}'
);
""",
            )
        )
        fault_stdout, fault_stderr = fault_process.communicate(timeout=5)
        client_connection_lost = (
            fault_process.returncode != 0
            and (
                "server closed the connection unexpectedly" in fault_stderr
                or "terminating connection" in fault_stderr
                or "connection to server was lost" in fault_stderr
            )
        )
        verification = _one_json(
            _run_sql(
                root,
                f"""
DO $block$
DECLARE attempt integer;
BEGIN
  FOR attempt IN 1..100 LOOP
    EXIT WHEN NOT EXISTS (
      SELECT 1 FROM pg_stat_activity WHERE pid = {backend_pid}
    );
    PERFORM pg_sleep(0.05);
  END LOOP;
END
$block$;
SELECT json_build_object(
  'verification_backend_pid', pg_backend_pid(),
  'backend_disappeared', NOT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE pid = {backend_pid}),
  'decisions', (SELECT count(*) FROM prototype_decision.decisions),
  'audits', (SELECT count(*) FROM prototype_decision.audits),
  'receipts', (SELECT count(*) FROM prototype_decision.receipts),
  'faulted_decisions', (SELECT count(*) FROM prototype_decision.decisions
    WHERE id = '{fault_id}'),
  'faulted_audits', (SELECT count(*) FROM prototype_decision.audits
    WHERE id = '{fault_id}'),
  'faulted_receipts', (SELECT count(*) FROM prototype_decision.receipts
    WHERE id = '{fault_id}'),
  'faulted_rows', (
    (SELECT count(*) FROM prototype_decision.decisions WHERE id = '{fault_id}')
    + (SELECT count(*) FROM prototype_decision.audits WHERE id = '{fault_id}')
    + (SELECT count(*) FROM prototype_decision.receipts WHERE id = '{fault_id}')),
  'orphan_audits', (SELECT count(*) FROM prototype_decision.audits a
    LEFT JOIN prototype_decision.decisions d USING(id) WHERE d.id IS NULL),
  'orphan_receipts', (SELECT count(*) FROM prototype_decision.receipts r
    LEFT JOIN prototype_decision.decisions d USING(id) WHERE d.id IS NULL));
""",
            )
        )
        faulted_rows = verification["faulted_rows"]
        automatic_rollback_verified = (
            verification.get("backend_disappeared") is True
            and faulted_rows == 0
            and verification.get("orphan_audits") == 0
            and verification.get("orphan_receipts") == 0
        )
        observation = {
            "fault_type": "postgresql-backend-termination",
            "fault_session_id": session_id,
            "fault_backend_pid": backend_pid,
            "control_backend_pid": termination.get("control_backend_pid"),
            "verification_backend_pid": verification.get(
                "verification_backend_pid"
            ),
            "readiness_marker": marker,
            "readiness_observed": True,
            "transaction_active_before_injection": transaction_active,
            "backend_identity_matched": backend_identity_matched,
            "termination_acknowledged": termination.get("acknowledged") is True,
            "explicit_rollback_issued": False,
            "client_connection_lost": client_connection_lost,
            "fault_client_exit_code": fault_process.returncode,
            "fault_client_stdout_after_marker": fault_stdout.strip(),
            "backend_disappeared": verification.get("backend_disappeared"),
            "verification_connection_fresh": (
                verification.get("verification_backend_pid")
                not in {
                    backend_pid,
                    termination.get("control_backend_pid"),
                }
            ),
            "automatic_rollback_verified": automatic_rollback_verified,
            "decisions": verification.get("decisions"),
            "audits": verification.get("audits"),
            "receipts": verification.get("receipts"),
            "faulted_decisions": verification.get("faulted_decisions"),
            "faulted_audits": verification.get("faulted_audits"),
            "faulted_receipts": verification.get("faulted_receipts"),
            "faulted_rows": faulted_rows,
            "orphan_audits": verification.get("orphan_audits"),
            "orphan_receipts": verification.get("orphan_receipts"),
            "postgres_version": version,
            "port": 5440,
        }
        observation["acceptance_recomputed"] = accepted_observation(observation)
        return observation
    finally:
        if fault_process is not None:
            _stop_owned_process(fault_process)
        _run_sql(root, CLEANUP_SQL)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(json.dumps(run(args.root.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
