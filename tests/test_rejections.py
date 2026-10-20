from __future__ import annotations

import copy
import json
import os
import subprocess
import sys

import pytest
from conftest import rtt, serial, spec_for

from embedded_trace import common
from embedded_trace.clock import unix_ns
from embedded_trace.common import TraceError, digest, parse_json, read_file, write_new
from embedded_trace.query import inspect, query, validate
from embedded_trace.timeline import correlate


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-01-01",
        "2026-01-01T00:00:00",
        "2026-01-01 00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00:00-00:00",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00.1234567890Z",
        "2026-01-01T00:00:00.١Z",
        "1969-12-31T23:59:59Z",
        1000,
        True,
    ],
)
def test_invalid_timestamps(stamp):
    with pytest.raises(TraceError):
        unix_ns(stamp)


def test_nanosecond_precision_and_timezone_conversion():
    assert unix_ns("1970-01-01T00:00:00.000000001Z") == 1
    assert unix_ns("2026-01-01T08:00:00+08:00") == unix_ns("2026-01-01T00:00:00Z")
    assert unix_ns("2026-01-01T00:00:00.123456789Z") % 10**9 == 123456789


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"n":NaN}',
        b'{"n":Infinity}',
        b'{"n":1e999}',
        b'{"s":"\\ud800"}',
        b"[]",
        b"{}\n{}",
        b'{"v":"\xff"}',
        b'{"a":' * 40 + b"0" + b"}" * 40,
    ],
)
def test_ambiguous_or_invalid_json(raw):
    with pytest.raises(TraceError):
        parse_json(raw)


@pytest.mark.parametrize("bad", [None, "F" * 64, "x", 1, False])
def test_source_requires_exact_hash_before_parsing(case, bad):
    path = case([b"A\n"])
    data = json.loads(path.read_text())
    data["sources"][0]["sha256"] = bad
    path.write_text(json.dumps(data))
    with pytest.raises(TraceError):
        correlate(path)


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/absolute",
        "C:/x",
        "a\\b",
        "CON",
        "NUL.txt",
        "a/../b",
        "foo:stream",
        "a//b",
        "trailing.",
        "trailing ",
    ],
)
def test_source_paths_are_portable_and_confined(case, name):
    path = case([b"A\n"])
    data = json.loads(path.read_text())
    data["sources"][0]["path"] = name
    path.write_text(json.dumps(data))
    with pytest.raises(TraceError):
        correlate(path)


@pytest.mark.parametrize(
    "mutation",
    [
        "sequence",
        "cursor",
        "length",
        "next_cursor",
        "hash",
        "count",
        "cleanup",
        "elapsed",
        "capture",
        "event",
        "selection",
        "plan",
    ],
)
def test_native_rtt_inconsistencies_are_rejected(tmp_path, mutation):
    rows = rtt([b"A\n"])
    if mutation in ("sequence", "cursor", "length", "next_cursor"):
        rows[2][mutation] += 1
    elif mutation == "hash":
        rows[-1]["payload_sha256"] = "0" * 64
    elif mutation == "count":
        rows[-1]["chunk_count"] = True
    elif mutation == "cleanup":
        rows[-1]["cleanup"]["channel_stopped"] = 1
    elif mutation == "elapsed":
        rows[2]["elapsed_ms"] = 0
    elif mutation == "capture":
        rows[2]["capture_id"] = "OTHER"
    elif mutation == "event":
        rows[2]["event"] = "unknown"
    elif mutation == "selection":
        rows[1]["channel"]["selection"] = {"other": "value"}
    else:
        rows[0]["plan"]["limits"] = []
    path = spec_for(tmp_path, [("rtt", "rtt-jsonl", rows, "host")])
    with pytest.raises(TraceError):
        correlate(path)


@pytest.mark.parametrize(
    "mutation", ["length", "base64", "canonical", "lifecycle", "timestamp", "step"]
)
def test_baud_inconsistencies_are_rejected(tmp_path, mutation):
    rows = serial([b"A\n"])
    if mutation == "length":
        rows[1]["bytes"] = True
    elif mutation == "base64":
        rows[1]["raw_base64"] = "invalid!"
    elif mutation == "canonical":
        rows[1].update(raw_base64="AB==", bytes=1)
    elif mutation == "lifecycle":
        rows.append(copy.deepcopy(rows[0]))
    elif mutation == "timestamp":
        rows[1]["ts"] = "not a timestamp"
    else:
        rows[1]["step"] = None
    with pytest.raises(TraceError):
        correlate(spec_for(tmp_path, [("uart", "baud-jsonl", rows, "host")]))


def test_changed_source_and_timeline_hashes_are_rejected(case, tmp_path):
    path = case([b"A\n"])
    output = tmp_path / "timeline.json"
    ref = write_new(output, correlate(path))
    (tmp_path / "uart.jsonl").write_bytes(b"changed\n")
    with pytest.raises(TraceError, match="SHA-256 differs"):
        correlate(path)
    with pytest.raises(TraceError):
        inspect(output, None)
    output.write_bytes(output.read_bytes() + b" ")
    with pytest.raises(TraceError, match="SHA-256 differs"):
        inspect(output, ref["sha256"])


def test_new_output_refuses_overwrite_and_reserved_names(case, tmp_path):
    document = correlate(case([b"A\n"]))
    output = tmp_path / "timeline.json"
    write_new(output, document)
    original = output.read_bytes()
    with pytest.raises(TraceError, match="output exists"):
        write_new(output, document)
    assert output.read_bytes() == original
    with pytest.raises(TraceError):
        write_new(tmp_path / "NUL", document)


def test_links_rejected_without_opening_target(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"original")
    link = tmp_path / "link"
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip("link creation unavailable")
    with pytest.raises(TraceError, match="links"):
        read_file(link, 100)


def test_unterminated_jsonl_is_rejected(case, tmp_path):
    path = case([b"A\n"])
    source = tmp_path / "uart.jsonl"
    source.write_bytes(source.read_bytes().rstrip(b"\n"))
    spec = json.loads(path.read_text())
    spec["sources"][0]["sha256"] = digest(source.read_bytes())
    path.write_text(json.dumps(spec))
    with pytest.raises(TraceError, match="newline"):
        correlate(path)


def test_file_line_record_and_event_limits(case, tmp_path, monkeypatch):
    import embedded_trace.adapters as adapters
    import embedded_trace.framing as framing
    import embedded_trace.timeline as timeline

    path = case([b"A\nB\n"])
    with pytest.raises(TraceError, match="byte limit"):
        read_file(tmp_path / "uart.jsonl", 1)
    for module, name, message in (
        (adapters, "MAX_RECORDS", "record count"),
        (framing, "MAX_EVENTS", "too many"),
        (framing, "MAX_LINE_BYTES", "line exceeds"),
        (timeline, "MAX_TOTAL_BYTES", "total source bytes"),
    ):
        with monkeypatch.context() as patch:
            patch.setattr(module, name, 1)
            with pytest.raises(TraceError, match=message):
                correlate(path)
    document = correlate(path)
    with monkeypatch.context() as patch:
        patch.setattr(common, "MAX_DOCUMENT_BYTES", 1)
        with pytest.raises(TraceError, match="output exceeds"):
            write_new(tmp_path / "not-created.json", document)
    assert not (tmp_path / "not-created.json").exists()


@pytest.mark.parametrize(
    "options",
    [
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"contains": "x" * 513},
        {"source": "missing"},
        {"domain": "missing"},
        {"since": "2027-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"},
    ],
)
def test_query_bounds(case, tmp_path, options):
    output = tmp_path / "timeline.json"
    ref = write_new(output, correlate(case([b"A\n"])))
    with pytest.raises(TraceError):
        query(output, ref["sha256"], **options)


def test_cli_runs_real_subprocesses_with_structured_errors(case, tmp_path):
    path = case([b"READY\n"])
    output = tmp_path / "timeline.json"

    def run(*arguments):
        return subprocess.run(
            [sys.executable, "-I", "-m", "embedded_trace", *map(str, arguments)],
            capture_output=True,
            encoding="utf-8",
            cwd=tmp_path,
            timeout=15,
        )

    result = run("correlate", path, "--output", output, "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    ref = report["data"]["output"]
    assert run("inspect", output, "--sha256", ref["sha256"], "--json").returncode == 0
    found = run("query", output, "--sha256", ref["sha256"], "--contains", "READY", "--json")
    assert json.loads(found.stdout)["data"]["matches_total"] == 1
    error = run("correlate", path, "--output", output, "--json")
    assert error.returncode == 2 and json.loads(error.stdout)["error"]["code"] == "OUTPUT_EXISTS"
    missing = run("correlate", tmp_path / "missing", "--output", tmp_path / "new", "--json")
    assert missing.returncode == 4 and not (tmp_path / "new").exists()


def test_no_hardware_or_process_launch_in_library(case, monkeypatch):
    import socket

    def forbidden(*_args, **_kwargs):
        raise AssertionError("unexpected process or network access")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    validate(correlate(case([b"READY\n"], [b"RTT\n"])))


def test_special_files_are_not_opened(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX FIFO check")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(TraceError, match="regular file"):
        read_file(fifo, 100)
