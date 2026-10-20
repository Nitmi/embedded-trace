from __future__ import annotations

import base64
import copy
import json
import socket
import subprocess
from pathlib import Path

import jsonschema
import pytest
from conftest import rtt, serial, spec_for

import embedded_trace.report as reporting
from embedded_trace.cli import main
from embedded_trace.common import TraceError, digest, write_new
from embedded_trace.query import query
from embedded_trace.report import report
from embedded_trace.timeline import SAFETY, correlate


def blocks(path):
    """Read the report's indented JSON blocks independently."""
    result = []
    pending = []
    for line in path.read_text(encoding="ascii").splitlines():
        if line.startswith("    "):
            pending.append(line[4:])
        elif pending:
            result.append(json.loads("\n".join(pending)))
            pending = []
    assert not pending
    return result


def test_report_is_deterministic_and_cites_full_payload(case, tmp_path):
    spec = case([b"REA", b"DY\r\n"], [b"RTT\n"], domains=("hostA", "hostB"))
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(spec))
    first, second = tmp_path / "first.md", tmp_path / "second.md"
    result = report(timeline, ref["sha256"], first, contains="READY")
    report(timeline, ref["sha256"], second, contains="READY")
    assert first.read_bytes() == second.read_bytes()
    assert result["output"]["sha256"] == digest(first.read_bytes())
    assert result["timeline"] == ref and result["matches_total"] == 1
    assert result["source_files_rechecked"] is False
    summary, uart, rtt_source, event = blocks(first)
    assert summary["clock_domains"] == [
        {"id": "hostA", "source_ids": ["uart"]},
        {"id": "hostB", "source_ids": ["rtt"]},
    ]
    assert all(summary[key] is False for key in SAFETY)
    assert uart["capture_outcome"] == rtt_source["capture_outcome"] == "succeeded"
    assert event["text_preview"] == "READY" and event["complete"] is True
    assert event["payload_sha256"] == digest(b"READY\r\n")
    assert base64.b64decode(event["raw_base64_preview"]) == b"READY\r\n"
    assert event["record_start"] == 2 and event["record_end"] == 3
    assert [span["record_index"] for span in event["segments_preview"]] == [2, 3]


@pytest.mark.parametrize("make,format_name", [(serial, "baud-jsonl"), (rtt, "rtt-jsonl")])
@pytest.mark.parametrize("outcome", ["failed", "partial"])
def test_capture_outcomes_and_incomplete_binary_are_explicit(tmp_path, make, format_name, outcome):
    rows = make([b"\xffTAIL"], complete=outcome != "partial")
    if outcome == "failed":
        rows[-1]["ok"] = False
        rows[-1]["error"] = {"code": "SYNTHETIC_FAILURE"}
    spec = spec_for(tmp_path, [("saved", format_name, rows, "host")])
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(spec))
    output = tmp_path / "report.md"
    result = report(timeline, ref["sha256"], output)
    assert result["capture_outcomes"] == {"saved": outcome}
    summary, source, *events = blocks(output)
    assert summary["status"] == "correlated_with_warnings"
    assert source["capture_outcome"] == outcome
    event = next(event for event in events if event["kind"] == "line")
    assert event["complete"] is False and event["text_preview"] is None
    assert base64.b64decode(event["raw_base64_preview"]) == b"\xffTAIL"


def test_previews_and_pages_are_bounded_without_altering_evidence(case, tmp_path):
    raw = b"A" * 600 + b"\n"
    spec = case([raw[index : index + 50] for index in range(0, len(raw), 50)])
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(spec))
    before = timeline.read_bytes()
    output = tmp_path / "report.md"
    result = report(timeline, ref["sha256"], output, contains="A", limit=1)
    event = blocks(output)[-1]
    assert event["text_preview"] == "A" * 512 and event["text_truncated"] is True
    assert len(event["raw_base64_preview"]) == 512 and event["raw_base64_truncated"] is True
    assert event["segment_count"] == 13 and len(event["segments_preview"]) == 8
    assert event["segments_truncated"] is True and event["payload_sha256"] == digest(raw)
    assert result["selected_count"] == 1 and timeline.read_bytes() == before
    empty = tmp_path / "empty.md"
    last = report(timeline, ref["sha256"], empty, contains="A", offset=1)
    assert last["selected_count"] == 0 and "No events on this page." in empty.read_text()


def test_report_filters_match_query_and_only_open_timeline(case, tmp_path, monkeypatch):
    spec = case([b"READY\n"], [b"READY\n"])
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(spec))
    filters = {
        "contains": "READY",
        "domain": "host",
        "source": "rtt",
        "since": "2026-01-01T00:00:00Z",
        "until": "2026-01-02T00:00:00Z",
        "limit": 1,
    }
    found = query(timeline, ref["sha256"], **filters)
    original_open = Path.open
    opens = []

    def guarded_open(path, *args, **kwargs):
        assert path in (timeline, tmp_path / "report.md"), "reopened a provenance path"
        opens.append(path)
        return original_open(path, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("Report must not start processes or use network")

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = report(timeline, ref["sha256"], tmp_path / "report.md", **filters)
    assert opens == [timeline, tmp_path / "report.md"]
    assert result["matches_total"] == found["matches_total"] == 1


def test_existing_010_timeline_and_missing_sources_are_supported(case, tmp_path):
    spec = case([b"READY\n"])
    document = correlate(spec)
    document["producer_version"] = "0.1.0"
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, document)
    (tmp_path / "uart.jsonl").rename(tmp_path / "moved.jsonl")
    spec.rename(tmp_path / "moved-spec.json")
    output = tmp_path / "report.md"
    result = report(timeline, ref["sha256"], output)
    assert blocks(output)[0]["timeline_producer_version"] == "0.1.0"
    assert result["timeline_hash_and_layout_verified"] is True
    assert result["source_files_rechecked"] is False
    assert any("native_json_preview" in event for event in blocks(output))


def test_untrusted_markdown_and_control_characters_stay_inert(case, tmp_path):
    payload = (
        b'````\n# heading\n<img src="https://example.invalid">\n[x](file:///x)\n\x1b[31m\r\x00'
    )
    payload += "\u202e 中文".encode()
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(case([payload])))
    output = tmp_path / "report.md"
    report(timeline, ref["sha256"], output)
    text = output.read_text(encoding="ascii")
    assert "\x1b" not in text and "\u202e" not in text and "\x00" not in text
    assert "\\u001b" in text and "\\u202e" in text and "\\u0000" in text
    assert all(
        line.startswith("    ")
        for line in text.splitlines()
        if any(token in line for token in ("<img", "file:///x", "````", "# heading"))
    )
    assert any(item.get("text_preview") == "# heading" for item in blocks(output))


@pytest.mark.parametrize(
    "filters",
    [
        {"limit": 0},
        {"limit": 101},
        {"limit": True},
        {"offset": -1},
        {"contains": "a" * 513},
        {"source": "absent"},
        {"domain": "absent"},
        {"since": "2027-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
    ],
)
def test_bad_filters_never_create_output(case, tmp_path, filters):
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(case([b"A\n"])))
    output = tmp_path / "never.md"
    with pytest.raises(TraceError):
        report(timeline, ref["sha256"], output, **filters)
    assert not output.exists()


def test_hash_layout_output_and_size_failures_do_not_replace_files(case, tmp_path, monkeypatch):
    document = correlate(case([b"A\n"]))
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, document)
    output = tmp_path / "report.md"
    with pytest.raises(TraceError, match="SHA-256 differs"):
        report(timeline, "0" * 64, output)
    assert not output.exists()
    broken = copy.deepcopy(document)
    broken["events"][0]["id"] = "changed"
    invalid = tmp_path / "invalid.json"
    bad_ref = write_new(invalid, broken)
    with pytest.raises(TraceError):
        report(invalid, bad_ref["sha256"], output)
    assert not output.exists()
    with monkeypatch.context() as patch:
        patch.setattr(reporting, "MAX_REPORT_BYTES", 1)
        with pytest.raises(TraceError, match="report exceeds"):
            report(timeline, ref["sha256"], output)
    assert not output.exists()
    output.write_bytes(b"preserve")
    with pytest.raises(TraceError, match="output exists"):
        report(timeline, ref["sha256"], output)
    assert output.read_bytes() == b"preserve"
    with pytest.raises(TraceError, match="output exists"):
        report(timeline, ref["sha256"], timeline)
    assert (
        timeline.read_bytes()
        == json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
        + b"\n"
    )


def test_report_cli_envelope_and_schema(case, tmp_path, capsys):
    timeline = tmp_path / "timeline.json"
    ref = write_new(timeline, correlate(case([b"READY\nREADY\n"])))
    output = tmp_path / "report.md"
    args = [
        "report",
        str(timeline),
        "--sha256",
        ref["sha256"],
        "--output",
        str(output),
        "--contains",
        "READY",
        "--limit",
        "1",
        "--json",
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["operation"] == "trace.report" and result["data"]["has_more"] is True
    assert all(result[key] is False for key in SAFETY)
    schema = json.loads((Path(__file__).parents[1] / "schemas/result.v1.schema.json").read_bytes())
    jsonschema.validate(result, schema)
    assert main(args) == 2
    failure = json.loads(capsys.readouterr().out)
    jsonschema.validate(failure, schema)
    assert failure["error"]["code"] == "OUTPUT_EXISTS"
