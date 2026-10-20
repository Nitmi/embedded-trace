from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest


def timestamp(index: int = 0) -> str:
    return (datetime(2026, 1, 1) + timedelta(milliseconds=index)).isoformat(
        timespec="milliseconds"
    ) + "Z"


def serial(chunks: list[bytes], *, complete: bool = True) -> list[dict]:
    rows = [{"type": "run_started", "ts": timestamp(), "name": "SYNTHETIC"}]
    for index, payload in enumerate(chunks, 1):
        rows.append(
            {
                "ts": timestamp(index),
                "type": "recv",
                "step": "monitor",
                "bytes": len(payload),
                "raw_base64": base64.b64encode(payload).decode(),
                "text": "Native display text is not used as raw evidence.",
            }
        )
    if complete:
        rows.append({"ts": timestamp(len(chunks) + 1), "type": "run_finished", "ok": True})
    return rows


def rtt(chunks: list[bytes], *, complete: bool = True) -> list[dict]:
    selection = {"core": 0, "channel": 0, "control_block": "0x20001000"}
    rows = [
        {
            "event": "capture.started",
            "plan": {
                "schema_version": "embedded-debugger.rtt-plan.v1",
                "operation": "rtt.capture",
                "selection": selection,
                "limits": {"maximum_bytes": 1024 * 1024, "duration_ms": 10},
            },
        },
        {"event": "rtt.channel", "channel": {"selection": selection}},
    ]
    cursor = 0
    for sequence, raw in enumerate(chunks):
        rows.append(
            {
                "event": "rtt.chunk",
                "encoding": "hex",
                "sequence": sequence,
                "cursor": cursor,
                "next_cursor": cursor + len(raw),
                "length": len(raw),
                "data": raw.hex(),
            }
        )
        cursor += len(raw)
    if complete:
        rows.append(
            {
                "event": "capture.finished",
                "ok": True,
                "stop_reason": "duration_limit",
                "bytes_captured": cursor,
                "next_cursor": cursor,
                "chunk_count": len(chunks),
                "payload_sha256": hashlib.sha256(b"".join(chunks)).hexdigest(),
                "cleanup": {
                    "channel_stopped": True,
                    "disconnected": True,
                    "stop_error": None,
                    "disconnect_error": None,
                },
            }
        )
    for index, row in enumerate(rows):
        row.update(
            schema_version="embedded-debugger.rtt-evidence.v1",
            capture_id="SYNTHETIC",
            timestamp=timestamp(index),
            elapsed_ms=0 if index == 0 else index + 10,
        )
    return rows


def save_rows(path: Path, rows: list[dict]) -> None:
    path.write_bytes(b"".join((json.dumps(row, ensure_ascii=True) + "\n").encode() for row in rows))


def spec_for(root: Path, entries: list[tuple[str, str, list[dict], str]]) -> Path:
    sources = []
    for identity, format_name, rows, domain in entries:
        path = root / (identity + ".jsonl")
        save_rows(path, rows)
        sources.append(
            {
                "id": identity,
                "format": format_name,
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "clock_domain": domain,
            }
        )
    spec = root / "input.json"
    spec.write_text(
        json.dumps({"schema_version": "embedded-trace.input.v1", "sources": sources}),
        encoding="utf-8",
    )
    return spec


@pytest.fixture
def case(tmp_path):
    def create(serial_chunks=None, rtt_chunks=None, domains=("host", "host")):
        entries = []
        if serial_chunks is not None:
            entries.append(("uart", "baud-jsonl", serial(serial_chunks), domains[0]))
        if rtt_chunks is not None:
            entries.append(("rtt", "rtt-jsonl", rtt(rtt_chunks), domains[1]))
        return spec_for(tmp_path, entries)

    return create
