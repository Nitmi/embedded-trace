from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import jsonschema
import pytest
from conftest import rtt, serial, spec_for

from embedded_trace.clock import unix_ns
from embedded_trace.common import TraceError, digest, json_bytes, write_new
from embedded_trace.query import inspect, query, validate
from embedded_trace.timeline import SAFETY, correlate


def lines(document, source=None):
    return sorted(
        [
            event
            for event in document["events"]
            if event["kind"] == "line" and (source is None or event["source_id"] == source)
        ],
        key=lambda event: event["source_ordinal"],
    )


def test_two_sources_reconstruct_utf8_crlf_and_provenance(case):
    spec = case([b"READY \xe4", b"\xb8\xad\r", b"\n\nTAIL"], [b"RTT\n"])
    before = {path: path.read_bytes() for path in spec.parent.iterdir()}
    document = correlate(spec)
    validate(document)
    messages = lines(document, "uart")
    assert [event["payload"]["text"] for event in messages] == ["READY 中", "", "TAIL"]
    assert [event["payload"]["terminator"] for event in messages] == ["crlf", "lf", None]
    joined = messages[0]
    assert (joined["record_start"], joined["record_end"]) == (2, 4)
    assert len(joined["payload"]["segments"]) == 3
    assert joined["time"]["first_recorded_at"] != joined["time"]["last_recorded_at"]
    assert all(document[key] is False for key in SAFETY)
    assert document["sources"][0]["warnings"]["unterminated_lines"] == 1
    assert all(path.read_bytes() == raw for path, raw in before.items())
    for source in document["sources"]:
        assert source["input"]["sha256"] == digest(Path(source["input"]["path"]).read_bytes())
    schema = json.loads((Path(__file__).parents[1] / "schemas/timeline.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(document)


def test_rtt_binary_lines_are_lossless(case):
    document = correlate(case(None, [b"\x00\xff\xe4\n", b"TAIL"]))
    validate(document)
    first, last = lines(document)
    assert first["payload"]["text"] is None and first["payload"]["utf8_valid"] is False
    assert base64.b64decode(first["payload"]["raw_base64"]) == b"\x00\xff\xe4\n"
    assert last["payload"]["complete"] is False
    assert document["sources"][0]["integrity"]["finish_payload_hash_verified"] is True


@pytest.mark.parametrize("format_name,make", [("baud-jsonl", serial), ("rtt-jsonl", rtt)])
def test_partial_and_failed_captures_remain_visible(tmp_path, format_name, make):
    rows = make([b"visible\n"], complete=False)
    spec = spec_for(tmp_path, [("saved", format_name, rows, "host")])
    document = correlate(spec)
    validate(document)
    assert document["sources"][0]["capture_outcome"] == "partial"
    assert document["status"] == "correlated_with_warnings"
    assert lines(document)[0]["payload"]["text"] == "visible"
    rows = make([b"visible\n"])
    rows[-1].update(ok=False, error={"code": "SYNTHETIC_FAILURE"})
    document = correlate(spec_for(tmp_path, [("saved", format_name, rows, "host")]))
    validate(document)
    assert document["sources"][0]["capture_outcome"] == "failed"


def test_rtt_attach_failure_without_channel(tmp_path):
    rows = rtt([])
    rows.pop(1)
    rows[-1].update(ok=False, attach_completed=False, error={"code": "TEST"})
    document = correlate(spec_for(tmp_path, [("rtt", "rtt-jsonl", rows, "host")]))
    validate(document)
    assert document["sources"][0]["capture_outcome"] == "failed"


def test_step_changes_and_tx_boundaries_never_join(tmp_path):
    rows = serial([b"FIRST", b"SECOND\n", b"CMD"])
    rows[2]["step"] = "next"
    rows[3].update(type="send", step="command")
    document = correlate(spec_for(tmp_path, [("uart", "baud-jsonl", rows, "host")]))
    validate(document)
    messages = lines(document)
    assert [row["payload"]["text"] for row in messages] == ["FIRST", "SECOND", "CMD"]
    assert messages[0]["payload"]["boundary"] == "step_change"
    assert messages[-1]["stream"] == "serial.tx"
    assert messages[-1]["payload"]["boundary"] == "record_end"


def test_domains_are_not_automatically_aligned(case):
    document = correlate(case([b"one\n"], [b"two\n"], domains=("hostA", "hostB")))
    validate(document)
    assert [group["id"] for group in document["clock_domains"]] == ["hostA", "hostB"]
    assert document["cross_source_clock_alignment_verified"] is False


def test_wall_clock_regression_and_intermediate_extrema_are_preserved(tmp_path):
    rows = serial([b"A", b"B", b"C\n"])
    rows[1]["ts"] = "2026-01-01T00:00:03Z"
    rows[2]["ts"] = "2026-01-01T00:00:01Z"
    rows[3]["ts"] = "2026-01-01T00:00:02Z"
    document = correlate(spec_for(tmp_path, [("uart", "baud-jsonl", rows, "host")]))
    validate(document)
    event = lines(document)[0]
    assert event["time"]["minimum_unix_ns"] == str(unix_ns(rows[2]["ts"]))
    assert event["time"]["maximum_unix_ns"] == str(unix_ns(rows[1]["ts"]))
    assert document["sources"][0]["warnings"]["wall_clock_regressions"] >= 1


def test_query_matches_cross_chunk_line_and_pages(case, tmp_path):
    document = correlate(case([b"REA", b"DY\nREADY\n"], [b"READY RTT\n"]))
    output = tmp_path / "timeline.json"
    ref = write_new(output, document)
    first = query(output, ref["sha256"], contains="READY", limit=1)
    assert first["matches_total"] == 3 and first["has_more"]
    second = query(output, ref["sha256"], contains="READY", offset=1, limit=1)
    assert first["events"][0]["id"] != second["events"][0]["id"]
    assert inspect(output, ref["sha256"])["source_files_rechecked"] is False
    assert query(output, ref["sha256"], contains="ready")["matches_total"] == 0
    assert query(output, ref["sha256"], source="rtt")["matches_total"] == 4


def test_queries_do_not_reopen_native_inputs(case, tmp_path):
    document = correlate(case([b"A\n"]))
    output = tmp_path / "timeline.json"
    ref = write_new(output, document)
    (tmp_path / "uart.jsonl").rename(tmp_path / "moved.jsonl")
    assert query(output, ref["sha256"], contains="A")["matches_total"] == 1
    assert inspect(output, ref["sha256"])["source_files_rechecked"] is False


def test_time_filter_uses_inclusive_interval_overlap(case, tmp_path):
    document = correlate(case([b"STA", b"RT\n"]))
    output = tmp_path / "timeline.json"
    ref = write_new(output, document)
    point = "2026-01-01T00:00:00.0015Z"
    assert (
        query(output, ref["sha256"], contains="START", since=point, until=point)["matches_total"]
        == 1
    )


def test_equal_time_order_is_deterministic(case):
    path = case([b"A\n"], [b"B\n"])
    assert json_bytes(correlate(path)) == json_bytes(correlate(path))


@pytest.mark.parametrize(
    "mutation",
    [
        "digest",
        "text",
        "ordinal",
        "order",
        "safety",
        "count",
        "span",
        "time",
        "domain",
        "termination",
    ],
)
def test_timeline_tampering_is_rejected(case, mutation):
    document = copy.deepcopy(correlate(case([b"A\n", b"B\n"])))
    event = next(row for row in document["events"] if row["kind"] == "line")
    if mutation == "digest":
        event["payload"]["sha256"] = "0" * 64
    elif mutation == "text":
        event["payload"]["text"] = "FORGED"
    elif mutation == "ordinal":
        event["source_ordinal"] = 0
    elif mutation == "order":
        document["events"].reverse()
    elif mutation == "safety":
        document["hardware_access"] = 0
    elif mutation == "count":
        document["event_count"] += 1
    elif mutation == "span":
        event["payload"]["segments"][0]["payload_byte_end"] += 1
    elif mutation == "time":
        event["time"]["minimum_unix_ns"] = "9" * 24
    elif mutation == "domain":
        event["clock_domain"] = "forged"
    else:
        event["payload"]["complete"] = 1
    with pytest.raises(TraceError):
        validate(document)
