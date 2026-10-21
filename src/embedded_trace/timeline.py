from __future__ import annotations

from pathlib import Path

from . import __version__
from .adapters import baud, records, rtt
from .common import (
    ID,
    MAX_RECORDS,
    MAX_SOURCE_BYTES,
    MAX_TOTAL_BYTES,
    SHA,
    parse_json,
    read_file,
    relative_source,
    require,
    text,
)
from .simulation import FORMAT as SIM_FORMAT
from .simulation import import_report

SAFETY = {
    "hardware_access": False,
    "executables_started": False,
    "authorization_granted": False,
    "hardware_identity_verified": False,
    "runtime_firmware_identity_verified": False,
    "cross_source_clock_alignment_verified": False,
    "target_event_time_verified": False,
}
ORDERING = "clock_domain_then_minimum_host_record_time_then_source_index_then_source_ordinal"


def correlate(path: Path) -> dict:
    raw, spec_ref = read_file(path, 64 * 1024)
    spec = parse_json(raw)
    require(
        set(spec) == {"schema_version", "sources"}
        and spec["schema_version"] == "embedded-trace.input.v1",
        "invalid trace input schema",
    )
    selected = spec["sources"]
    require(isinstance(selected, list) and 1 <= len(selected) <= 8, "select 1..8 sources")
    source_ids = set()
    paths = set()
    sources = []
    events: list[dict] = []
    total = 0
    record_count = 0
    for source_index, entry in enumerate(selected):
        require(
            isinstance(entry, dict)
            and set(entry) == {"id", "format", "path", "sha256", "clock_domain"},
            "invalid source entry fields",
        )
        identity = text(entry["id"], "source ID", 64)
        domain = text(entry["clock_domain"], "clock_domain", 64)
        require(
            ID.fullmatch(identity) is not None and identity not in source_ids,
            "invalid or duplicate source ID",
        )
        require(ID.fullmatch(domain) is not None, "invalid clock domain")
        require(
            entry["format"] in ("baud-jsonl", "rtt-jsonl", SIM_FORMAT), "unsupported source format"
        )
        require(
            isinstance(entry["sha256"], str) and SHA.fullmatch(entry["sha256"]) is not None,
            "source requires a lowercase SHA-256",
        )
        source_ids.add(identity)
        source_path = relative_source(Path(spec_ref["path"]).parent, entry["path"])
        payload, reference = read_file(source_path, MAX_SOURCE_BYTES, entry["sha256"])
        require(reference["path"] not in paths, "same input path selected twice")
        paths.add(reference["path"])
        total += len(payload)
        require(total <= MAX_TOTAL_BYTES, "total source bytes exceed limit", "LIMIT_EXCEEDED")
        rows = [] if entry["format"] == SIM_FORMAT else records(payload)
        source = {
            "id": identity,
            "format": entry["format"],
            "clock_domain": domain,
            "clock_domain_is_user_declaration": True,
            "source_index": source_index,
            "input": reference,
            "record_count": len(rows),
            "event_count": 0,
            "payload_bytes": 0,
            "warnings": {},
            "native_summary_verified": False,
            "integrity": {"input_hash_verified": True, "record_structure_verified": True},
        }
        start = len(events)
        if entry["format"] == SIM_FORMAT:
            total += import_report(payload, source_path, source, events)
        else:
            (baud if entry["format"] == "baud-jsonl" else rtt)(rows, source, events)
        require(total <= MAX_TOTAL_BYTES, "total evidence bytes exceed limit", "LIMIT_EXCEEDED")
        record_count += source["record_count"]
        require(record_count <= MAX_RECORDS, "total source records exceed limit", "LIMIT_EXCEEDED")
        local = sorted(
            events[start:], key=lambda event: (event["record_end"], event["source_ordinal"])
        )
        for ordinal, event in enumerate(local, 1):
            event.update(id=f"{identity}:{ordinal}", source_ordinal=ordinal)
        events[start:] = local
        if source["capture_outcome"] != "succeeded":
            source["warnings"]["capture_" + source["capture_outcome"]] = 1
        sources.append(source)
    for source in sources:
        require(
            all(
                (other["format"] == SIM_FORMAT) == (source["format"] == SIM_FORMAT)
                for other in sources
                if other["clock_domain"] == source["clock_domain"]
            ),
            "simulation and device captures require distinct clock domains",
        )
    indexes = {source["id"]: source["source_index"] for source in sources}
    events.sort(
        key=lambda event: (
            event["clock_domain"],
            int(event["time"]["minimum_unix_ns"]),
            indexes[event["source_id"]],
            event["source_ordinal"],
        )
    )
    domains = sorted({source["clock_domain"] for source in sources})
    return {
        "schema_version": "embedded-trace.timeline.v1",
        "producer_version": __version__,
        "scope": "host_only_saved_log_correlation",
        **SAFETY,
        "status": "correlated_with_warnings"
        if any(source["warnings"] for source in sources)
        else "correlated",
        "input_spec": spec_ref,
        "ordering": ORDERING,
        "clock_domains": [
            {
                "id": domain,
                "source_ids": [
                    source["id"] for source in sources if source["clock_domain"] == domain
                ],
            }
            for domain in domains
        ],
        "sources": sources,
        "event_count": len(events),
        "events": events,
    }
