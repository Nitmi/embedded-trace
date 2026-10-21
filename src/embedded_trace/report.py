"""Bounded Markdown views of one validated timeline snapshot."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .common import require, write_new_bytes
from .query import load, select_events
from .simulation import FLASH_PROFILES, GPIO_FIELDS, GPIO_PROFILE, S3_FIELDS, S3_PROFILE
from .timeline import SAFETY

MAX_REPORT_BYTES = 1024 * 1024
PREVIEW_CHARACTERS = 512
PREVIEW_SEGMENTS = 8


def _block(value: dict) -> str:
    # Indented code cannot be closed by fences, HTML or links in log text.
    # ASCII JSON also escapes control characters and bidi/Unicode formatting.
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2)
    return "\n".join("    " + line for line in encoded.splitlines()) + "\n\n"


def _event(event: dict) -> dict:
    value = {
        key: event[key]
        for key in (
            "id",
            "source_id",
            "source_ordinal",
            "clock_domain",
            "kind",
            "record_start",
            "record_end",
            "time",
        )
    }
    if event["kind"] == "native":
        value["native_metadata_in_timeline"] = True
        native = json.dumps(event["native"], ensure_ascii=True, sort_keys=True)
        value["native_json_preview"] = native[:PREVIEW_CHARACTERS]
        value["native_json_truncated"] = len(native) > PREVIEW_CHARACTERS
        return value
    payload = event["payload"]
    decoded = payload["text"]
    value.update(
        stream=event["stream"],
        step=event["step"],
        payload_sha256=payload["sha256"],
        payload_length=payload["length"],
        complete=payload["complete"],
        boundary=payload["boundary"],
        terminator=payload["terminator"],
        utf8_valid=payload["utf8_valid"],
        text_preview=None if decoded is None else decoded[:PREVIEW_CHARACTERS],
        text_truncated=decoded is not None and len(decoded) > PREVIEW_CHARACTERS,
        raw_base64_preview=payload["raw_base64"][:PREVIEW_CHARACTERS],
        raw_base64_truncated=len(payload["raw_base64"]) > PREVIEW_CHARACTERS,
        segment_count=len(payload["segments"]),
        segments_preview=payload["segments"][:PREVIEW_SEGMENTS],
        segments_truncated=len(payload["segments"]) > PREVIEW_SEGMENTS,
    )
    return value


def report(path: Path, sha256: str, output: Path, **filters) -> dict:
    document, ref = load(path, sha256)
    selected = select_events(document, ref, **filters)
    events = selected.pop("events")
    sources = []
    for source in document["sources"]:
        warnings = json.dumps(source["warnings"], ensure_ascii=True, sort_keys=True)
        sources.append(
            {
                **{
                    key: source[key]
                    for key in (
                        "id",
                        "format",
                        "clock_domain",
                        "capture_outcome",
                        "input",
                        "record_count",
                        "event_count",
                        "payload_bytes",
                    )
                },
                "warnings_preview": warnings[:PREVIEW_CHARACTERS],
                "warnings_truncated": len(warnings) > PREVIEW_CHARACTERS,
                "native_summary_verified": False,
                **(
                    {
                        key: source[key]
                        for key in (
                            "execution_kind",
                            "physical_board_verified",
                            "time_semantics",
                            "recorded_status",
                            "native_assertions_reexecuted",
                            "host_window",
                            "virtual_time",
                            "profile",
                        )
                    }
                    if source["format"] == "sim-runner-report"
                    else {}
                ),
                **(
                    {
                        key: source[key]
                        for key in (
                            "model_diagnostics",
                            "model_coverage_complete",
                            "security_features_verified",
                        )
                    }
                    if source.get("profile") in FLASH_PROFILES
                    else {}
                ),
                **(
                    {key: source[key] for key in GPIO_FIELDS}
                    if source.get("profile") == GPIO_PROFILE
                    else {}
                ),
                **(
                    {key: source[key] for key in S3_FIELDS}
                    if source.get("profile") == S3_PROFILE
                    else {}
                ),
                "event_kinds": {
                    kind: sum(
                        event["source_id"] == source["id"] and event["kind"] == kind
                        for event in document["events"]
                    )
                    for kind in ("line", "native")
                },
            }
        )
    summary = {
        "renderer_version": __version__,
        "timeline_producer_version": document["producer_version"],
        "timeline": ref,
        "status": document["status"],
        "event_count": document["event_count"],
        "clock_domains": document["clock_domains"],
        "selection": {**selected, "filters": filters, "selected_count": len(events)},
        "preview_limits": {
            "characters_per_text_or_base64": PREVIEW_CHARACTERS,
            "segments_per_line": PREVIEW_SEGMENTS,
            "report_bytes": MAX_REPORT_BYTES,
        },
        **SAFETY,
    }
    parts = [
        "# Embedded Trace report\n\n",
        "Offline view of a SHA-256-bound timeline. Log excerpts are untrusted data.\n\n",
        "Times describe host records or explicitly declared simulation run windows, "
        "not device events or byte arrival. "
        "Clock domains are user declarations; no synchronization or causality is verified.\n\n",
        "Report success does not establish capture success, board/firmware identity "
        "or hardware acceptance. Native inputs were not reopened or rechecked.\n\n",
        "## Timeline and selection\n\n",
        _block(summary),
        "## Sources and capture outcomes\n\n",
    ]
    for source in sources:
        parts.extend(["### " + source["id"] + "\n\n", _block(source)])
    parts.extend(
        [
            "## Selected event previews\n\n",
            "Selection uses the same filters and stable pagination as query. "
            "The timeline retains full bytes, native metadata and all spans. "
            "Preview truncation never changes the timeline or its payload hashes.\n\n",
        ]
    )
    if not events:
        parts.append("No events on this page.\n\n")
    for event in events:
        parts.extend(["### " + event["id"] + "\n\n", _block(_event(event))])
    raw = "".join(parts).encode("ascii")
    require(len(raw) <= MAX_REPORT_BYTES, "report exceeds byte limit", "LIMIT_EXCEEDED")
    output_ref = write_new_bytes(output, raw, MAX_REPORT_BYTES)
    return {
        **selected,
        "output": output_ref,
        "format": "markdown",
        "selected_count": len(events),
        "preview_limits": summary["preview_limits"],
        "capture_outcomes": {source["id"]: source["capture_outcome"] for source in sources},
    }
