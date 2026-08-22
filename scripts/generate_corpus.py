#!/usr/bin/env python3
"""Generate Testament's harmless, deterministic research trace corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable


GENERATOR_VERSION = "1.0.0"
CORPUS_VERSION = "1.0.0"
ROOT_SEED = "testament-synthetic-trace-corpus-v1"
MANIFEST_PATH = "docs/research/corpus/manifest.json"
FIXTURE_ROOT = "fixtures/research-corpus"
VALIDATION_IDS = ["VAL-READY-012", "VAL-READY-013"]
RESEARCH_DEPENDENCIES = [
    "RES-STUDY-TRACE-LANDSCAPE-001",
    "RES-STUDY-ABUSE-MISUSE-001",
    "RES-STUDY-STRIDE-001",
    "RES-STUDY-DATA-INVENTORY-001",
]


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def jsonl_bytes(records: list[dict[str, Any]]) -> bytes:
    return b"".join(json_bytes(record) for record in records)


def digest_blocks(seed: str, label: str, count: int, width: int = 64) -> str:
    blocks = [
        hashlib.sha256(f"{seed}:{label}:{counter}".encode("utf-8")).hexdigest()
        for counter in range((count + width - 1) // width)
    ]
    return "".join(blocks)[:count]


def seed_suffix(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def openai_stream_tool(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    return jsonl_bytes(
        [
            {
                "type": "response.created",
                "response": {"id": f"resp_synthetic_{suffix}", "model": "example-model"},
                "sequence_number": 0,
            },
            {
                "type": "response.output_item.added",
                "item": {
                    "id": f"call_synthetic_{suffix}",
                    "type": "function_call",
                    "name": "lookup_weather",
                    "arguments": '{"city":"Exampleville"}',
                },
                "sequence_number": 1,
            },
            {
                "type": "response.completed",
                "response": {
                    "id": f"resp_synthetic_{suffix}",
                    "status": "completed",
                    "output_text": "The synthetic forecast is mild.",
                },
                "sequence_number": 2,
            },
        ]
    )


def anthropic_retry_stream(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    events = [
        ("message_start", {"type": "message_start", "message": {"id": f"msg_synthetic_{suffix}"}}),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Synthetic hello."},
            },
        ),
        (
            "message_stop",
            {
                "type": "message_stop",
                "retry": {"attempt": 2, "retry_of": f"attempt_synthetic_{suffix}"},
            },
        ),
    ]
    return b"".join(
        f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'), sort_keys=True)}\n\n".encode(
            "utf-8"
        )
        for name, payload in events
    )


def gemini_multimodal(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    return json_bytes(
        {
            "model": "models/example-gemini",
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "Describe the synthetic diagram."},
                        {
                            "fileData": {
                                "fileUri": f"urn:testament:synthetic:image:{suffix}",
                                "mimeType": "image/png",
                            }
                        },
                    ],
                }
            ],
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [{"text": "It contains two labeled boxes."}],
                    }
                }
            ],
        }
    )


def bedrock_late_missing_lineage(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    return jsonl_bytes(
        [
            {
                "event_id": f"bedrock_synthetic_{suffix}_002",
                "provider": "bedrock",
                "arrival_ordinal": 2,
                "event_time": "2026-01-01T00:00:01Z",
                "parent_event_id": None,
                "lineage_status": "missing",
                "output": {"message": {"role": "assistant", "content": [{"text": "Second."}]}},
            },
            {
                "event_id": f"bedrock_synthetic_{suffix}_001",
                "provider": "bedrock",
                "arrival_ordinal": 1,
                "event_time": "2026-01-01T00:00:00Z",
                "late": True,
                "output": {"message": {"role": "assistant", "content": [{"text": "First."}]}},
            },
        ]
    )


def giant_json(seed: str) -> bytes:
    return json_bytes(
        {
            "fixture": "giant-json",
            "payload": digest_blocks(seed, "giant-json", 1_100_000),
            "synthetic": True,
        }
    )


def giant_jsonl(seed: str) -> bytes:
    return jsonl_bytes(
        [
            {
                "fixture": "giant-jsonl",
                "ordinal": ordinal,
                "payload": digest_blocks(seed, f"giant-jsonl:{ordinal}", 192),
                "synthetic": True,
            }
            for ordinal in range(4096)
        ]
    )


def malformed_json(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    return f'{{"fixture":"malformed-json-{suffix}","synthetic":true,"items":[1,2,}}\r\n'.encode(
        "utf-8"
    )


def malformed_jsonl(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    return (
        f'{{"fixture":"{suffix}","ordinal":0,"synthetic":true}}\n'
        f'{{"fixture":"{suffix}","ordinal":1,"synthetic":true\n'
        f'{{"fixture":"{suffix}","ordinal":2,"synthetic":true}}\n'
    ).encode(
        "utf-8"
    )


def authorized_twin(seed: str) -> bytes:
    return json_bytes(
        {
            "scenario_id": f"authorized-security-simulation-{seed_suffix(seed)}",
            "authorized": True,
            "purpose": "Defensive tabletop exercise in an isolated training environment.",
            "content": "Abstract alert labels only; no operational instructions or target data.",
            "review_required": True,
        }
    )


def abuse_signals(seed: str) -> bytes:
    suffix = seed_suffix(seed)
    scenarios = [
        ("cyber", "Defensive lab alert; no exploit details."),
        ("cbrn", "Specialist-review marker; no technical procedure."),
        ("fraud", "Fictional transaction-pattern alert."),
        ("compromised-accounts", "Synthetic impossible-travel alert."),
        ("model-extraction", "Synthetic repeated-query-volume alert."),
        ("evasion", "Abstract policy-evasion label."),
        ("prompt-injection", "Untrusted-content boundary alert without a payload."),
        ("insider-risk", "Synthetic unusual-export-volume alert."),
        ("coordinated-actors", "Synthetic shared-pattern cluster alert."),
    ]
    return jsonl_bytes(
        [
            {
                "scenario_id": f"abuse-synthetic-{suffix}-{index:02d}",
                "risk": risk,
                "summary": summary,
                "synthetic": True,
                "contains_actionable_harm": False,
                "requires_human_review": True,
            }
            for index, (risk, summary) in enumerate(scenarios, start=1)
        ]
    )


FixtureBuilder = Callable[[str], bytes]


FIXTURES: list[dict[str, Any]] = [
    {
        "id": "FIX-PROVIDER-OPENAI-STREAM-TOOL-001",
        "file": "provider-openai-stream-tool.jsonl",
        "classes": ["provider", "stream", "tool"],
        "format": "jsonl",
        "media_type": "application/x-ndjson",
        "provider": "openai",
        "recipe": "openai_stream_tool",
        "parse_status": "complete",
        "record_count": 3,
        "assertions": ["Preserve event order, tool arguments, native IDs, and exact line bytes."],
        "builder": openai_stream_tool,
    },
    {
        "id": "FIX-PROVIDER-ANTHROPIC-RETRY-STREAM-001",
        "file": "provider-anthropic-retry-stream.sse",
        "classes": ["provider", "stream", "retry"],
        "format": "sse",
        "media_type": "text/event-stream",
        "provider": "anthropic",
        "recipe": "anthropic_retry_stream",
        "parse_status": "complete",
        "record_count": 3,
        "assertions": ["Preserve SSE framing, retry identity, event names, and exact bytes."],
        "builder": anthropic_retry_stream,
    },
    {
        "id": "FIX-PROVIDER-GEMINI-MULTIMODAL-001",
        "file": "provider-gemini-multimodal.json",
        "classes": ["provider", "multimodal"],
        "format": "json",
        "media_type": "application/json",
        "provider": "gemini",
        "recipe": "gemini_multimodal",
        "parse_status": "complete",
        "record_count": 1,
        "assertions": ["Retain text and external artifact reference without fetching it."],
        "builder": gemini_multimodal,
    },
    {
        "id": "FIX-PROVIDER-BEDROCK-LATE-LINEAGE-001",
        "file": "provider-bedrock-late-missing-lineage.jsonl",
        "classes": ["provider", "late", "missing-lineage"],
        "format": "jsonl",
        "media_type": "application/x-ndjson",
        "provider": "bedrock",
        "recipe": "bedrock_late_missing_lineage",
        "parse_status": "complete",
        "record_count": 2,
        "assertions": ["Keep event, arrival, and lineage states distinct; do not invent a parent."],
        "builder": bedrock_late_missing_lineage,
    },
    {
        "id": "FIX-GIANT-JSON-001",
        "file": "giant.json",
        "classes": ["giant"],
        "format": "json",
        "media_type": "application/json",
        "provider": None,
        "recipe": "giant_json",
        "parse_status": "complete",
        "record_count": 1,
        "assertions": ["Retain a JSON scalar larger than one million bytes exactly."],
        "builder": giant_json,
    },
    {
        "id": "FIX-GIANT-JSONL-001",
        "file": "giant.jsonl",
        "classes": ["giant"],
        "format": "jsonl",
        "media_type": "application/x-ndjson",
        "provider": None,
        "recipe": "giant_jsonl",
        "parse_status": "complete",
        "record_count": 4096,
        "assertions": ["Retain all 4096 lines and their delimiters exactly."],
        "builder": giant_jsonl,
    },
    {
        "id": "FIX-MALFORMED-JSON-001",
        "file": "malformed.json",
        "classes": ["malformed"],
        "format": "json",
        "media_type": "application/json",
        "provider": None,
        "recipe": "malformed_json",
        "parse_status": "parse-failed",
        "record_count": 0,
        "assertions": ["Retain malformed CRLF-terminated bytes without repair or projection."],
        "builder": malformed_json,
    },
    {
        "id": "FIX-MALFORMED-JSONL-001",
        "file": "malformed.jsonl",
        "classes": ["malformed"],
        "format": "jsonl",
        "media_type": "application/x-ndjson",
        "provider": None,
        "recipe": "malformed_jsonl",
        "parse_status": "partial",
        "record_count": 2,
        "assertions": ["Retain valid neighbors and malformed middle-line bytes independently."],
        "builder": malformed_jsonl,
    },
    {
        "id": "FIX-AUTHORIZED-TWIN-001",
        "file": "authorized-security-twin.json",
        "classes": ["authorized-twin"],
        "format": "json",
        "media_type": "application/json",
        "provider": None,
        "recipe": "authorized_twin",
        "parse_status": "complete",
        "record_count": 1,
        "assertions": ["Keep authorization and defensive purpose available to human review."],
        "builder": authorized_twin,
    },
    {
        "id": "FIX-ABUSE-SIGNALS-001",
        "file": "abuse-signals.jsonl",
        "classes": ["abuse"],
        "format": "jsonl",
        "media_type": "application/x-ndjson",
        "provider": None,
        "recipe": "abuse_signals",
        "parse_status": "complete",
        "record_count": 9,
        "assertions": ["Treat labels as synthetic review signals, not findings or policy decisions."],
        "builder": abuse_signals,
    },
]


def fixture_record(definition: dict[str, Any], content: bytes) -> dict[str, Any]:
    fixture_seed = hashlib.sha256(
        f"{ROOT_SEED}:{definition['id']}".encode("utf-8")
    ).hexdigest()
    return {
        "id": definition["id"],
        "version": "1.0.0",
        "path": f"{FIXTURE_ROOT}/{definition['file']}",
        "classes": definition["classes"],
        "format": definition["format"],
        "media_type": definition["media_type"],
        "provider": definition["provider"],
        "byte_count": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "provenance": {
            "kind": "project-created-synthetic",
            "generator": "scripts/generate_corpus.py",
            "generator_version": GENERATOR_VERSION,
            "seed": fixture_seed,
            "recipe": definition["recipe"],
            "source_dependencies": RESEARCH_DEPENDENCIES,
            "customer_or_production_data": False,
        },
        "redistribution_license": {
            "spdx": "Apache-2.0",
            "copyright": "Testament contributors",
            "notice": "Project-created synthetic fixture; redistribution permitted under Apache-2.0.",
        },
        "expectations": {
            "raw_authority": "exact-bytes",
            "parse_status": definition["parse_status"],
            "record_count": definition["record_count"],
            "semantic_assertions": definition["assertions"],
            "normative_conformance": False,
        },
        "privacy_review": {
            "status": "completed",
            "reviewed_at": "2026-08-21",
            "reviewer_role": "corpus author safety self-review; independent review pending",
            "result": "safe-synthetic",
            "personal_data": False,
            "live_credentials": False,
            "customer_data": False,
        },
        "safety_review": {
            "status": "completed",
            "result": "harmless-abstract-content",
            "actionable_harm": False,
            "limitations": "Fixtures exercise trace shape and review labels only; they are not detection efficacy evidence.",
        },
    }


def generated_content() -> dict[str, bytes]:
    generated: dict[str, bytes] = {}
    for definition in FIXTURES:
        fixture_seed = hashlib.sha256(
            f"{ROOT_SEED}:{definition['id']}".encode("utf-8")
        ).hexdigest()
        generated[f"{FIXTURE_ROOT}/{definition['file']}"] = definition["builder"](
            fixture_seed
        )
    return generated


def manifest_document(content: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "deliverable_id": "RES-CORPUS-SYNTHETIC-TRACE-001",
        "feature_id": "synthetic-corpus-and-reproducibility",
        "validation_ids": VALIDATION_IDS,
        "status": "informative-research",
        "version": CORPUS_VERSION,
        "generated_at": "2026-08-21",
        "generator": {
            "path": "scripts/generate_corpus.py",
            "version": GENERATOR_VERSION,
            "runtime": "Python 3 standard library",
            "root_seed": ROOT_SEED,
            "seed_derivation": "SHA-256(root_seed + ':' + fixture_id)",
            "canonicalization": "Generator-defined UTF-8 bytes; JSON objects use sorted compact keys and one LF.",
        },
        "license_policy": {
            "allowed_spdx": ["Apache-2.0"],
            "default": "Apache-2.0",
            "third_party_content": False,
        },
        "safety_policy": {
            "synthetic_only": True,
            "customer_data_forbidden": True,
            "production_data_forbidden": True,
            "pii_forbidden": True,
            "live_credentials_forbidden": True,
            "actionable_harm_forbidden": True,
        },
        "fixtures": [
            fixture_record(definition, content[f"{FIXTURE_ROOT}/{definition['file']}"])
            for definition in FIXTURES
        ],
        "limitations": [
            "Provider-shaped fixtures are project-created approximations, not provider certification vectors.",
            "Abuse labels are harmless abstractions and do not demonstrate detector accuracy.",
            "The corpus is informative research until a separate immutable promotion decision approves selected bytes.",
        ],
    }


def manifest_bytes(content: dict[str, bytes]) -> bytes:
    return (json.dumps(manifest_document(content), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def expected_files() -> dict[str, bytes]:
    content = generated_content()
    return {**content, MANIFEST_PATH: manifest_bytes(content)}


def check(root: Path) -> list[str]:
    failures: list[str] = []
    files = expected_files()
    for relative, expected in files.items():
        path = root / relative
        try:
            actual = path.read_bytes()
        except OSError as error:
            failures.append(f"{relative}: {error}")
            continue
        if actual != expected:
            failures.append(f"{relative}: generated bytes differ")
    return failures


def write(root: Path, files: dict[str, bytes]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.write:
        files = expected_files()
        write(root, files)
        print(json.dumps({"status": "written", "files": len(files)}))
        return 0
    failures = check(root)
    report = {"status": "pass" if not failures else "fail", "failures": failures}
    print(json.dumps(report, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
