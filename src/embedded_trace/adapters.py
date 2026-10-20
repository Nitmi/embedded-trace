from __future__ import annotations

import base64
import binascii
import re

from .clock import unix_ns
from .common import (
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    TraceError,
    digest,
    integer,
    parse_json,
    require,
    text,
)
from .framing import Framer

RTT_SCHEMA = "embedded-debugger.rtt-evidence.v1"


def records(raw: bytes) -> list[dict]:
    require(raw.endswith(b"\n"), "JSONL must end with a complete newline-terminated record")
    lines = raw.split(b"\n")[:-1]
    require(1 <= len(lines) <= MAX_RECORDS, "invalid JSONL record count", "LIMIT_EXCEEDED")
    result = []
    for index, line in enumerate(lines, 1):
        require(0 < len(line) <= MAX_RECORD_BYTES, f"invalid JSONL record size at {index}")
        result.append(parse_json(line))
    return result


def context(row: dict, index: int, previous: int | None, source: dict, timestamp: str) -> dict:
    stamp = unix_ns(timestamp)
    if previous is not None and stamp < previous:
        warnings = source["warnings"]
        warnings["wall_clock_regressions"] = warnings.get("wall_clock_regressions", 0) + 1
    return {"index": index, "timestamp": timestamp, "ns": stamp}


def decode_base64(value: object) -> bytes:
    value = text(value, "raw_base64", MAX_RECORD_BYTES)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise TraceError("INVALID_INPUT", "invalid payload base64") from error
    require(base64.b64encode(raw).decode("ascii") == value, "noncanonical payload base64")
    return raw


def baud(rows: list[dict], source: dict, events: list[dict]) -> None:
    framer = Framer(source, events)
    previous = None
    started = None
    terminal = None
    for index, row in enumerate(rows, 1):
        kind = text(row.get("type"), "baud event type", 64)
        require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", kind) is not None, "invalid baud type")
        ctx = context(row, index, previous, source, row.get("ts"))
        previous = ctx["ns"]
        if kind in ("run_started", "probe_started"):
            require(index == 1 and started is None, "multiple or misplaced baud starts")
            started = kind
        if kind in ("run_finished", "probe_finished"):
            require(index == len(rows) and type(row.get("ok")) is bool, "invalid baud finish")
            require(
                started is None or kind == started.replace("started", "finished"),
                "baud lifecycle differs",
            )
            terminal = row["ok"]
        if kind in ("error", "step_failed", "guard_blocked") or (
            kind == "assert" and row.get("ok") is False
        ):
            source["warnings"]["native_failure_recorded"] = 1
        if kind in ("recv", "send"):
            raw = decode_base64(row.get("raw_base64"))
            require(
                integer(row.get("bytes"), "baud payload size") == len(raw),
                "baud byte count differs",
            )
            step = text(row.get("step"), "baud step")
            source["payload_bytes"] += len(raw)
            framer.feed(
                "serial.rx" if kind == "recv" else "serial.tx",
                step,
                raw,
                ctx,
                atomic=kind == "send",
            )
            if not raw:
                framer.metadata(row, ctx)
        else:
            framer.metadata(row, ctx)
    framer.finish()
    source["capture_outcome"] = (
        "succeeded" if terminal is True else "failed" if terminal is False else "partial"
    )
    source["time_semantics"] = "baud_recorder_event_creation_not_byte_arrival"
    source["integrity"]["finish_payload_hash_verified"] = None


def rtt(rows: list[dict], source: dict, events: list[dict]) -> None:
    framer = Framer(source, events)
    first = rows[0]
    require(first.get("event") == "capture.started", "RTT must begin with capture.started")
    capture_id = text(first.get("capture_id"), "capture_id", 128)
    require(bool(capture_id), "missing capture ID")
    plan = first.get("plan")
    require(
        isinstance(plan, dict) and plan.get("schema_version") == "embedded-debugger.rtt-plan.v1",
        "invalid RTT plan declaration",
    )
    require(plan.get("operation") == "rtt.capture", "unexpected RTT plan operation")
    require(
        isinstance(plan.get("limits"), dict) and isinstance(plan.get("selection"), dict),
        "RTT plan lacks limits or selection",
    )
    maximum = integer(plan["limits"].get("maximum_bytes"), "RTT maximum bytes", 1, 1024 * 1024)
    previous = None
    elapsed = 0
    cursor = 0
    chunks = 0
    payload = bytearray()
    channel = False
    finish = None
    for index, row in enumerate(rows, 1):
        require(
            row.get("schema_version") == RTT_SCHEMA and row.get("capture_id") == capture_id,
            "RTT schema or capture ID differs",
        )
        ctx = context(row, index, previous, source, row.get("timestamp"))
        previous = ctx["ns"]
        elapsed = integer(row.get("elapsed_ms"), "elapsed_ms", elapsed)
        ctx["elapsed_ms"] = elapsed
        kind = row.get("event")
        if kind == "capture.started":
            require(index == 1 and elapsed == 0, "invalid RTT start")
        elif kind == "rtt.channel":
            require(index == 2 and not channel, "invalid RTT channel position")
            declared = row.get("channel")
            require(
                isinstance(declared, dict) and declared.get("selection") == plan.get("selection"),
                "RTT channel selection differs",
            )
            channel = True
        elif kind == "rtt.chunk":
            require(channel and chunks < 4096, "chunk without channel or too many chunks")
            require(
                integer(row.get("sequence"), "sequence") == chunks, "RTT sequence discontinuity"
            )
            require(integer(row.get("cursor"), "cursor") == cursor, "RTT cursor discontinuity")
            encoded = text(row.get("data"), "RTT hex", 8192)
            require(
                row.get("encoding") == "hex"
                and re.fullmatch(r"[0-9a-f]+", encoded) is not None
                and len(encoded) % 2 == 0,
                "invalid RTT hex",
            )
            raw = bytes.fromhex(encoded)
            require(
                integer(row.get("length"), "chunk length", 1, 4096) == len(raw),
                "RTT length differs",
            )
            cursor += len(raw)
            require(
                cursor <= maximum and integer(row.get("next_cursor"), "next_cursor") == cursor,
                "RTT next_cursor differs",
            )
            chunks += 1
            payload.extend(raw)
            framer.feed("rtt.up", "capture", raw, ctx)
        elif kind == "capture.finished":
            require(index == len(rows) and type(row.get("ok")) is bool, "invalid RTT finish")
            finish = row
            if row["ok"]:
                require(channel, "successful RTT finish without channel")
                require(
                    integer(row.get("bytes_captured"), "bytes_captured") == cursor
                    and integer(row.get("next_cursor"), "final cursor") == cursor,
                    "RTT final bytes differ",
                )
                require(
                    integer(row.get("chunk_count"), "chunk_count") == chunks
                    and row.get("payload_sha256") == digest(payload),
                    "RTT final count or hash differs",
                )
                cleanup = row.get("cleanup")
                require(
                    isinstance(cleanup, dict)
                    and set(cleanup)
                    == {"channel_stopped", "disconnected", "stop_error", "disconnect_error"},
                    "RTT successful cleanup differs",
                )
                require(
                    cleanup["channel_stopped"] is True
                    and cleanup["disconnected"] is True
                    and cleanup["stop_error"] is None
                    and cleanup["disconnect_error"] is None,
                    "RTT successful cleanup differs",
                )
                require(
                    row.get("stop_reason") in ("byte_limit", "duration_limit", "chunk_limit"),
                    "invalid stop reason",
                )
                if row["stop_reason"] == "byte_limit":
                    require(cursor == maximum, "RTT byte limit not reached")
                if row["stop_reason"] == "chunk_limit":
                    require(chunks == 4096, "RTT chunk limit not reached")
                if row["stop_reason"] == "duration_limit":
                    require(
                        elapsed >= integer(plan["limits"].get("duration_ms"), "duration_ms", 1),
                        "RTT duration not reached",
                    )
            else:
                require(isinstance(row.get("error"), dict), "failed RTT finish lacks error")
        else:
            require(False, "unsupported RTT event")
        if kind != "rtt.chunk":
            framer.metadata(row, ctx)
    framer.finish()
    source["payload_bytes"] = cursor
    source["capture_outcome"] = (
        "partial" if finish is None else "succeeded" if finish["ok"] else "failed"
    )
    source["time_semantics"] = "native_host_chunk_record_creation_not_target_event_time"
    source["integrity"]["finish_payload_hash_verified"] = finish is not None and finish["ok"]
