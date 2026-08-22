#!/usr/bin/env python3
"""External per-sample resource accounting for disposable prototypes."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import threading
import time
from typing import Any


ACCOUNTING_VERSION = "2.0.0"
LOCAL_SCOPE = "worker_descendant_tree"
POSTGRES_SCOPE = "postgres_container_cgroup"
LOCAL_SOURCE = "external_ps_process_table"
POSTGRES_SOURCE = "docker_stats_container_cgroup"
LOCAL_ISOLATION = "fresh_process_group"
POSTGRES_ISOLATION = "fresh_service_lifecycle_and_worker_process_group"
REQUIRED_ACCOUNTING_FIELDS = {
    "accounting_version",
    "scope",
    "metric",
    "source",
    "target",
    "isolation",
    "descendants_included",
    "peak_rss_bytes",
    "budget_bytes",
    "hard_limit_bytes",
    "within_budget",
}


class AccountingError(RuntimeError):
    """Fail-closed accounting or lifecycle error."""


@dataclass(frozen=True)
class ObservedProcess:
    returncode: int
    stdout: str
    stderr: str
    accounting: dict[str, Any]
    limit_exceeded: bool


@dataclass(frozen=True)
class ServicesManifest:
    path: Path
    start: str
    stop: str
    healthcheck: str
    port: int

    @classmethod
    def from_path(cls, path: Path) -> "ServicesManifest":
        resolved = path.resolve()
        if resolved.name != "services.yaml" or not resolved.is_file():
            raise AccountingError("PostgreSQL lifecycle requires services.yaml")
        text = resolved.read_text(encoding="utf-8")
        lines = text.splitlines()
        in_services = False
        in_postgres = False
        values: dict[str, Any] = {}
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            if indent == 0:
                in_services = stripped == "services:"
                in_postgres = False
                continue
            if in_services and indent == 2 and stripped.endswith(":"):
                in_postgres = stripped == "postgres:"
                continue
            if in_postgres and indent == 4 and ":" in stripped:
                key, raw = stripped.split(":", 1)
                raw = raw.strip()
                if raw.startswith('"') and raw.endswith('"'):
                    values[key] = json.loads(raw)
                elif re.fullmatch(r"[0-9]+", raw):
                    values[key] = int(raw)
        required = {"start", "stop", "healthcheck", "port"}
        if required - set(values):
            raise AccountingError(
                "services.yaml postgres entry must define start, stop, "
                "healthcheck, and port"
            )
        if values["port"] != 5440:
            raise AccountingError("services.yaml postgres port must be 5440")
        for key in ("start", "stop", "healthcheck"):
            value = values[key]
            if not isinstance(value, str) or "5440" not in value:
                raise AccountingError(
                    f"services.yaml postgres {key} must explicitly bind port 5440"
                )
        return cls(
            path=resolved,
            start=values["start"],
            stop=values["stop"],
            healthcheck=values["healthcheck"],
            port=values["port"],
        )


def validate_accounting(value: Any) -> None:
    if not isinstance(value, dict) or REQUIRED_ACCOUNTING_FIELDS - set(value):
        raise AccountingError("resource accounting omits required fields")
    scope = value.get("scope")
    expected = {
        LOCAL_SCOPE: (
            "aggregate_peak_resident_bytes",
            LOCAL_SOURCE,
            LOCAL_ISOLATION,
        ),
        POSTGRES_SCOPE: (
            "peak_container_cgroup_resident_bytes",
            POSTGRES_SOURCE,
            POSTGRES_ISOLATION,
        ),
    }
    if scope not in expected:
        raise AccountingError("legacy or unknown resource accounting scope")
    metric, source, isolation = expected[scope]
    peak = value.get("peak_rss_bytes")
    budget = value.get("budget_bytes")
    hard_limit = value.get("hard_limit_bytes")
    within = value.get("within_budget")
    if (
        value.get("accounting_version") != ACCOUNTING_VERSION
        or value.get("metric") != metric
        or value.get("source") != source
        or value.get("isolation") != isolation
        or not isinstance(value.get("target"), str)
        or not value["target"]
        or value.get("descendants_included") is not True
        or not isinstance(peak, int)
        or peak < 0
        or not isinstance(budget, int)
        or budget <= 0
        or hard_limit != budget
        or not isinstance(within, bool)
        or within is not (peak <= budget)
    ):
        raise AccountingError(
            "resource accounting is missing, legacy, non-isolated, or "
            "inconsistent with recomputed budget status"
        )


def valid_resource_sample(
    sample: Any,
    budgets: dict[str, Any],
    expected_scope: str,
) -> bool:
    if (
        not isinstance(sample, dict)
        or "process_max_rss_bytes" in sample
        or not isinstance(sample.get("elapsed_ms"), (int, float))
        or sample["elapsed_ms"] > budgets.get("max_elapsed_ms", -1)
    ):
        return False
    accounting = sample.get("resource_accounting")
    try:
        validate_accounting(accounting)
    except AccountingError:
        return False
    return (
        accounting.get("scope") == expected_scope
        and accounting.get("budget_bytes")
        == budgets.get("max_process_rss_bytes")
        and accounting.get("hard_limit_bytes")
        == budgets.get("max_process_rss_bytes")
        and accounting.get("within_budget") is True
        and sample.get("observation", {}).get("worker_completed") is True
    )


def _accounting(
    *,
    scope: str,
    metric: str,
    source: str,
    target: str,
    isolation: str,
    peak_rss_bytes: int,
    budget_bytes: int,
    hard_limit_bytes: int,
) -> dict[str, Any]:
    value = {
        "accounting_version": ACCOUNTING_VERSION,
        "scope": scope,
        "metric": metric,
        "source": source,
        "target": target,
        "isolation": isolation,
        "descendants_included": True,
        "peak_rss_bytes": peak_rss_bytes,
        "budget_bytes": budget_bytes,
        "hard_limit_bytes": hard_limit_bytes,
        "within_budget": peak_rss_bytes <= budget_bytes,
    }
    validate_accounting(value)
    return value


ProcessIdentity = tuple[int, str]
ProcessRecord = tuple[int, int, int, str]


def _process_table() -> dict[int, ProcessRecord]:
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,pgid=,rss=,lstart="],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AccountingError(
            f"external process observer failed: {result.stderr.strip()}"
        )
    table: dict[int, ProcessRecord] = {}
    try:
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 9:
                raise ValueError("short ps row")
            pid, parent, process_group, rss_kib = (
                int(value) for value in fields[:4]
            )
            table[pid] = (
                parent,
                process_group,
                rss_kib * 1024,
                " ".join(fields[4:]),
            )
    except (TypeError, ValueError) as error:
        raise AccountingError("external process observer returned invalid data") from error
    return table


def _descendant_rss(
    table: dict[int, ProcessRecord],
    root_pid: int,
    known_descendants: set[ProcessIdentity],
) -> int:
    root = table.get(root_pid)
    if root is not None:
        known_descendants.add((root_pid, root[3]))
    live_pids = {
        pid
        for pid, started_at in known_descendants
        if pid in table and table[pid][3] == started_at
    }
    for pid, (_, process_group, _, started_at) in table.items():
        if process_group == root_pid:
            known_descendants.add((pid, started_at))
            live_pids.add(pid)
    changed = True
    while changed:
        changed = False
        for pid, (parent, _, _, started_at) in table.items():
            if parent in live_pids and pid not in live_pids:
                known_descendants.add((pid, started_at))
                live_pids.add(pid)
                changed = True
    return sum(table[pid][2] for pid in live_pids)


def _terminate_process_group(
    process: subprocess.Popen[str],
    known_descendants: set[ProcessIdentity] | None = None,
) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    current = _process_table()
    for pid, started_at in known_descendants or set():
        if pid == process.pid:
            continue
        if pid not in current or current[pid][3] != started_at:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def observe_local_process(
    command: list[str],
    *,
    cwd: Path,
    budget_bytes: int,
    hard_limit_bytes: int,
    timeout_ms: int,
    poll_interval_seconds: float = 0.02,
) -> ObservedProcess:
    if budget_bytes != hard_limit_bytes:
        raise AccountingError("hard limit must equal the unchanged RSS budget")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    started = time.monotonic()
    peak = 0
    limit_exceeded = False
    known_descendants: set[ProcessIdentity] = set()
    try:
        while True:
            peak = max(
                peak,
                _descendant_rss(
                    _process_table(),
                    process.pid,
                    known_descendants,
                ),
            )
            if peak > hard_limit_bytes:
                limit_exceeded = True
                _terminate_process_group(process, known_descendants)
                break
            if process.poll() is not None:
                current = _process_table()
                live_descendants = {
                    identity
                    for identity in known_descendants
                    if identity[0] != process.pid
                    and identity[0] in current
                    and current[identity[0]][3] == identity[1]
                }
                if live_descendants:
                    _terminate_process_group(process, live_descendants)
                break
            if (time.monotonic() - started) * 1000 > timeout_ms:
                _terminate_process_group(process, known_descendants)
                break
            time.sleep(poll_interval_seconds)
        stdout, stderr = process.communicate()
    except BaseException:
        _terminate_process_group(process, known_descendants)
        process.communicate()
        raise
    accounting = _accounting(
        scope=LOCAL_SCOPE,
        metric="aggregate_peak_resident_bytes",
        source=LOCAL_SOURCE,
        target=f"worker_pid:{process.pid}",
        isolation=LOCAL_ISOLATION,
        peak_rss_bytes=peak,
        budget_bytes=budget_bytes,
        hard_limit_bytes=hard_limit_bytes,
    )
    return ObservedProcess(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        accounting=accounting,
        limit_exceeded=limit_exceeded,
    )


_MEMORY_UNITS = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "KiB": 1024,
    "MB": 1000**2,
    "MiB": 1024**2,
    "GB": 1000**3,
    "GiB": 1024**3,
}


def _memory_bytes(value: str) -> int:
    value = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", value).strip()
    match = re.fullmatch(
        r"\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*(?:/.*)?",
        value,
    )
    if not match or match.group(2) not in _MEMORY_UNITS:
        raise AccountingError(f"invalid Docker cgroup memory value: {value!r}")
    return int(float(match.group(1)) * _MEMORY_UNITS[match.group(2)])


def _run_lifecycle(command: str, *, timeout: float = 60) -> None:
    result = subprocess.run(
        ["/bin/sh", "-c", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AccountingError(
            f"services.yaml lifecycle command failed: {result.stderr.strip()}"
        )


def _healthcheck(manifest: ServicesManifest) -> None:
    deadline = time.monotonic() + 60
    last_error = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["/bin/sh", "-c", manifest.healthcheck],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode == 0:
            return
        last_error = result.stderr.strip()
        time.sleep(0.5)
    raise AccountingError(
        f"services.yaml postgres healthcheck did not pass: {last_error}"
    )


def _postgres_container_id(cwd: Path) -> str:
    result = subprocess.run(
        ["docker", "compose", "ps", "-q", "postgres"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    identifiers = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or len(identifiers) != 1:
        raise AccountingError("could not resolve one postgres container target")
    return identifiers[0]


def _start_stats(container_id: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "docker",
            "stats",
            "--format",
            "{{.MemUsage}}",
            container_id,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _stats_reader(
    process: subprocess.Popen[str],
    samples: queue.Queue[int | AccountingError],
) -> None:
    assert process.stdout is not None
    try:
        for line in process.stdout:
            visible = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line).strip()
            if visible and visible != "-- / --":
                samples.put(_memory_bytes(line))
    except AccountingError as error:
        samples.put(error)


def _close_stats_pipes(process: subprocess.Popen[str]) -> None:
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()


def observe_postgres_process(
    command: list[str],
    *,
    cwd: Path,
    manifest: ServicesManifest,
    budget_bytes: int,
    hard_limit_bytes: int,
    timeout_ms: int,
) -> ObservedProcess:
    if budget_bytes != hard_limit_bytes:
        raise AccountingError("hard limit must equal the unchanged RSS budget")
    process: subprocess.Popen[str] | None = None
    stats: subprocess.Popen[str] | None = None
    peak = 0
    stats_samples = 0
    limit_exceeded = False
    stats_values: queue.Queue[int | AccountingError] = queue.Queue()
    stats_thread: threading.Thread | None = None
    try:
        _run_lifecycle(manifest.start)
        _healthcheck(manifest)
        container_id = _postgres_container_id(cwd)
        stats = _start_stats(container_id)
        stats_thread = threading.Thread(
            target=_stats_reader,
            args=(stats, stats_values),
            daemon=True,
        )
        stats_thread.start()
        try:
            first = stats_values.get(timeout=10)
        except queue.Empty as error:
            raise AccountingError(
                "Docker cgroup observer produced no initial sample"
            ) from error
        if isinstance(first, AccountingError):
            raise first
        peak = first
        stats_samples = 1
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        started = time.monotonic()
        while True:
            while True:
                try:
                    observed = stats_values.get_nowait()
                except queue.Empty:
                    break
                if isinstance(observed, AccountingError):
                    raise observed
                peak = max(peak, observed)
                stats_samples += 1
                if peak > hard_limit_bytes:
                    limit_exceeded = True
                    _terminate_process_group(process)
                    break
            if limit_exceeded or process.poll() is not None:
                break
            if stats.poll() is not None:
                stats_stderr = stats.stderr.read() if stats.stderr else ""
                raise AccountingError(
                    "Docker cgroup observer exited during the sample: "
                    f"{stats_stderr.strip()}"
                )
            if (time.monotonic() - started) * 1000 > timeout_ms:
                _terminate_process_group(process)
                break
            time.sleep(0.01)
        if stats.poll() is None:
            stats.send_signal(signal.SIGINT)
            try:
                stats.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stats.kill()
                stats.wait()
        if stats_thread is not None:
            stats_thread.join(timeout=5)
        _close_stats_pipes(stats)
        while True:
            try:
                observed = stats_values.get_nowait()
            except queue.Empty:
                break
            if isinstance(observed, AccountingError):
                raise observed
            peak = max(peak, observed)
            stats_samples += 1
        stdout, stderr = process.communicate()
        if stats_samples == 0:
            raise AccountingError(
                "Docker cgroup observer captured no PostgreSQL memory sample"
            )
        accounting = _accounting(
            scope=POSTGRES_SCOPE,
            metric="peak_container_cgroup_resident_bytes",
            source=POSTGRES_SOURCE,
            target=f"container_id:{container_id}",
            isolation=POSTGRES_ISOLATION,
            peak_rss_bytes=peak,
            budget_bytes=budget_bytes,
            hard_limit_bytes=hard_limit_bytes,
        )
        return ObservedProcess(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            accounting=accounting,
            limit_exceeded=limit_exceeded,
        )
    except BaseException:
        if process is not None:
            _terminate_process_group(process)
            process.communicate()
        if stats is not None and stats.poll() is None:
            stats.send_signal(signal.SIGINT)
            try:
                stats.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stats.kill()
                stats.wait()
        if stats_thread is not None:
            stats_thread.join(timeout=5)
        if stats is not None:
            _close_stats_pipes(stats)
        raise
    finally:
        _run_lifecycle(manifest.stop)
