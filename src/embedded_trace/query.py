from __future__ import annotations

from pathlib import Path

from .adapters import decode_base64
from .clock import unix_ns
from .common import (
    ID,
    MAX_DOCUMENT_BYTES,
    MAX_EVENTS,
    MAX_LINE_BYTES,
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    MAX_SOURCE_BYTES,
    MAX_TOTAL_BYTES,
    SHA,
    digest,
    integer,
    parse_json,
    read_file,
    require,
    text,
)
from .timeline import ORDERING, SAFETY


def reference(value: object, maximum: int) -> None:
    require(isinstance(value, dict), "invalid file reference")
    require(
        isinstance(value.get("sha256"), str) and SHA.fullmatch(value["sha256"]) is not None,
        "invalid reference digest",
    )
    text(value.get("path"), "reference path", 2048)
    integer(value.get("size_bytes"), "reference size", 0, maximum)


def validate(document: dict) -> None:
    text(document.get("producer_version"), "producer_version", 64)
    require(
        document.get("schema_version") == "embedded-trace.timeline.v1", "invalid timeline schema"
    )
    require(
        document.get("scope") == "host_only_saved_log_correlation"
        and document.get("ordering") == ORDERING,
        "invalid timeline scope or ordering",
    )
    require(all(document.get(key) is False for key in SAFETY), "invalid timeline safety claims")
    reference(document.get("input_spec"), 64 * 1024)
    sources = document.get("sources")
    require(isinstance(sources, list) and 1 <= len(sources) <= 8, "invalid timeline sources")
    source_map = {}
    ordinals: dict[str, set[int]] = {}
    native_records: dict[str, set[int]] = {}
    native_bytes: dict[str, int] = {}
    for index, source in enumerate(sources):
        require(isinstance(source, dict), "invalid timeline source")
        identity = text(source.get("id"), "source ID", 64)
        domain = text(source.get("clock_domain"), "clock domain", 64)
        require(
            ID.fullmatch(identity) is not None
            and identity not in source_map
            and ID.fullmatch(domain) is not None,
            "invalid source identity",
        )
        require(
            integer(source.get("source_index"), "source index") == index, "invalid source ordering"
        )
        require(source.get("format") in ("baud-jsonl", "rtt-jsonl"), "invalid source format")
        require(
            source.get("capture_outcome") in ("succeeded", "failed", "partial"),
            "invalid capture outcome",
        )
        require(
            source.get("clock_domain_is_user_declaration") is True
            and source.get("native_summary_verified") is False,
            "invalid source verification claim",
        )
        reference(source.get("input"), MAX_SOURCE_BYTES)
        integer(source.get("record_count"), "record count", 1, MAX_RECORDS)
        integer(source.get("event_count"), "source event count", 0, MAX_EVENTS)
        integer(source.get("payload_bytes"), "payload bytes", 0, MAX_SOURCE_BYTES)
        require(isinstance(source.get("warnings"), dict), "invalid warnings")
        for value in source["warnings"].values():
            integer(value, "warning count", 1, MAX_RECORDS)
        integrity = source.get("integrity")
        require(
            isinstance(integrity, dict)
            and integrity.get("input_hash_verified") is True
            and integrity.get("record_structure_verified") is True,
            "invalid source integrity fields",
        )
        expected_finish = (
            None if source["format"] == "baud-jsonl" else source["capture_outcome"] == "succeeded"
        )
        require(
            integrity.get("finish_payload_hash_verified") is expected_finish,
            "invalid finish integrity claim",
        )
        text(source.get("time_semantics"), "time semantics", 128)
        source_map[identity] = source
        ordinals[identity] = set()
        native_records[identity] = set()
        native_bytes[identity] = 0
    require(
        sum(source["record_count"] for source in sources) <= MAX_RECORDS
        and sum(source["input"]["size_bytes"] for source in sources) <= MAX_TOTAL_BYTES,
        "source totals exceed limits",
    )
    require(
        document.get("status")
        == (
            "correlated_with_warnings"
            if any(source["warnings"] for source in sources)
            else "correlated"
        ),
        "timeline status differs",
    )
    expected_domains = [
        {
            "id": domain,
            "source_ids": [source["id"] for source in sources if source["clock_domain"] == domain],
        }
        for domain in sorted({source["clock_domain"] for source in sources})
    ]
    require(document.get("clock_domains") == expected_domains, "clock domains differ")
    events = document.get("events")
    require(isinstance(events, list) and len(events) <= MAX_EVENTS, "invalid timeline events")
    require(
        integer(document.get("event_count"), "event count") == len(events), "event count differs"
    )
    previous = None
    for event in events:
        require(
            isinstance(event, dict) and isinstance(event.get("source_id"), str),
            "invalid timeline event",
        )
        require(event["source_id"] in source_map, "unknown event source")
        source = source_map[event["source_id"]]
        ordinal = integer(event.get("source_ordinal"), "source ordinal", 1, source["event_count"])
        require(ordinal not in ordinals[source["id"]], "duplicate event ordinal")
        ordinals[source["id"]].add(ordinal)
        require(
            event.get("id") == f"{source['id']}:{ordinal}"
            and event.get("clock_domain") == source["clock_domain"],
            "event identity differs",
        )
        first = integer(event.get("record_start"), "record_start", 1, source["record_count"])
        last = integer(event.get("record_end"), "record_end", first, source["record_count"])
        timing = event.get("time")
        require(isinstance(timing, dict), "invalid event time")
        first_ns = unix_ns(timing.get("first_recorded_at"))
        last_ns = unix_ns(timing.get("last_recorded_at"))
        for key in ("minimum_unix_ns", "maximum_unix_ns"):
            value = text(timing.get(key), key, 24)
            require(
                value.isascii()
                and value.isdecimal()
                and (value == "0" or not value.startswith("0")),
                "invalid decimal timestamp",
            )
        low, high = int(timing["minimum_unix_ns"]), int(timing["maximum_unix_ns"])
        require(
            0
            <= low
            <= min(first_ns, last_ns)
            <= max(first_ns, last_ns)
            <= high
            < 253402300800 * 10**9,
            "invalid event time envelope",
        )
        ordering = (source["clock_domain"], low, source["source_index"], ordinal)
        require(previous is None or ordering >= previous, "events not in declared order")
        previous = ordering
        if event.get("kind") == "native":
            require(
                first == last
                and first_ns == last_ns == low == high
                and isinstance(event.get("native"), dict),
                "invalid native event",
            )
            native_records[source["id"]].add(first)
            continue
        require(event.get("kind") == "line", "invalid event kind")
        require(
            event.get("stream")
            in (("serial.rx", "serial.tx") if source["format"] == "baud-jsonl" else ("rtt.up",)),
            "invalid stream",
        )
        text(event.get("step"), "step")
        payload = event.get("payload")
        elapsed = event.get("elapsed_ms")
        require(
            isinstance(elapsed, dict) and set(elapsed) == {"first", "last"},
            "invalid line elapsed time",
        )
        if source["format"] == "baud-jsonl":
            require(
                elapsed["first"] is None and elapsed["last"] is None,
                "baud has no elapsed capture clock",
            )
        else:
            integer(elapsed["last"], "last elapsed", integer(elapsed["first"], "first elapsed"))
        require(isinstance(payload, dict), "invalid line payload")
        raw = decode_base64(payload.get("raw_base64"))
        require(
            integer(payload.get("length"), "payload length", 1, MAX_LINE_BYTES) == len(raw)
            and payload.get("sha256") == digest(raw),
            "line length or hash differs",
        )
        terminator = "crlf" if raw.endswith(b"\r\n") else "lf" if raw.endswith(b"\n") else None
        require(
            payload.get("terminator") == terminator
            and payload.get("complete") is (terminator is not None),
            "line termination differs",
        )
        content = raw[:-2] if terminator == "crlf" else raw[:-1] if terminator else raw
        require(b"\n" not in content, "payload contains more than one line")
        try:
            decoded = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            decoded = None
        require(
            payload.get("text") == decoded and payload.get("utf8_valid") is (decoded is not None),
            "UTF-8 view differs",
        )
        require(
            payload.get("boundary") in ("newline", "record_end", "step_change", "end_of_input"),
            "invalid line boundary",
        )
        require(
            (payload["boundary"] == "newline") is (terminator is not None),
            "boundary differs from terminator",
        )
        spans = payload.get("segments")
        require(isinstance(spans, list) and 1 <= len(spans) <= MAX_RECORDS, "invalid line segments")
        total = 0
        cursor = None
        previous_record = first
        for span in spans:
            require(isinstance(span, dict), "invalid byte span")
            previous_record = integer(
                span.get("record_index"), "record index", previous_record, last
            )
            native_records[source["id"]].add(previous_record)
            start = integer(span.get("payload_byte_start"), "payload start", 0, MAX_RECORD_BYTES)
            end = integer(span.get("payload_byte_end"), "payload end", start + 1, MAX_RECORD_BYTES)
            begin = integer(span.get("stream_byte_start"), "stream start", 0, MAX_SOURCE_BYTES)
            finish = integer(span.get("stream_byte_end"), "stream end", begin + 1, MAX_SOURCE_BYTES)
            require(
                end - start == finish - begin and (cursor is None or begin == cursor),
                "segment span differs",
            )
            cursor = finish
            total += end - start
        require(
            spans[0]["record_index"] == first
            and spans[-1]["record_index"] == last
            and total == len(raw),
            "segment total differs",
        )
        native_bytes[source["id"]] += len(raw)
    for source in sources:
        require(
            len(ordinals[source["id"]]) == source["event_count"], "source event inventory differs"
        )
        require(
            native_records[source["id"]] == set(range(1, source["record_count"] + 1)),
            "native record coverage differs",
        )
        require(
            native_bytes[source["id"]] == source["payload_bytes"], "source payload total differs"
        )
        local = sorted(
            (event for event in events if event["source_id"] == source["id"]),
            key=lambda event: event["source_ordinal"],
        )
        require(
            [event["record_end"] for event in local]
            == sorted(event["record_end"] for event in local),
            "source completion order differs",
        )
        cursors = {}
        for event in local:
            if event["kind"] == "line":
                stream = event["stream"]
                spans = event["payload"]["segments"]
                require(
                    spans[0]["stream_byte_start"] == cursors.get(stream, 0),
                    "source stream cursor discontinuity",
                )
                cursors[stream] = spans[-1]["stream_byte_end"]


def load(path: Path, sha256: str) -> tuple[dict, dict]:
    require(
        isinstance(sha256, str) and SHA.fullmatch(sha256) is not None,
        "timeline requires a lowercase SHA-256",
    )
    raw, ref = read_file(path, MAX_DOCUMENT_BYTES, sha256)
    document = parse_json(raw)
    validate(document)
    return document, ref


def inspect(path: Path, sha256: str) -> dict:
    document, ref = load(path, sha256)
    return {
        "timeline": ref,
        "status": document["status"],
        "event_count": document["event_count"],
        "source_count": len(document["sources"]),
        "clock_domains": document["clock_domains"],
        "capture_outcomes": {
            source["id"]: source["capture_outcome"] for source in document["sources"]
        },
        "source_files_rechecked": False,
        "timeline_hash_and_layout_verified": True,
    }


def query(
    path: Path,
    sha256: str,
    *,
    contains: str | None = None,
    source: str | None = None,
    domain: str | None = None,
    since: str | None = None,
    until: str | None = None,
    offset: int = 0,
    limit: int = 20,
) -> dict:
    integer(offset, "offset", 0, MAX_EVENTS)
    integer(limit, "limit", 1, 100)
    if contains is not None:
        text(contains, "contains", 512)
    low = unix_ns(since) if since is not None else 0
    high = unix_ns(until) if until is not None else 253402300800 * 10**9 - 1
    require(low <= high, "since must not exceed until")
    document, ref = load(path, sha256)
    require(
        source is None or source in {entry["id"] for entry in document["sources"]},
        "unknown source filter",
    )
    require(
        domain is None or domain in {entry["id"] for entry in document["clock_domains"]},
        "unknown clock domain filter",
    )
    matches = [
        event
        for event in document["events"]
        if (source is None or event["source_id"] == source)
        and (domain is None or event["clock_domain"] == domain)
        and int(event["time"]["maximum_unix_ns"]) >= low
        and int(event["time"]["minimum_unix_ns"]) <= high
        and (
            contains is None
            or (
                event["kind"] == "line"
                and event["payload"]["text"] is not None
                and contains in event["payload"]["text"]
            )
        )
    ]
    return {
        "timeline": ref,
        "matches_total": len(matches),
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < len(matches),
        "events": matches[offset : offset + limit],
        "time_filter_semantics": "inclusive_host_record_interval_overlap",
        "source_files_rechecked": False,
        "timeline_hash_and_layout_verified": True,
    }
