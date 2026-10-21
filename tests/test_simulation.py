"""Synthetic native reports test offline integrity, provenance and window semantics."""

import base64
import copy
import json
from pathlib import Path

import jsonschema
import pytest

from embedded_trace.common import TraceError, digest
from embedded_trace.query import validate
from embedded_trace.simulation import BOUNDARIES
from embedded_trace.timeline import correlate


def evidence(
    root,
    *,
    qemu=True,
    passed=True,
    flash=False,
    uart=b"READY\r\nBUILD abc\r\nHEARTBEAT 00000001\r\n",
):
    root.mkdir()
    files = {
        "runtime-lock.json": b"{}\n",
        "firmware.elf" if qemu else "firmware.bin": b"synthetic firmware",
        "model.json" if qemu else "model.repl": b"synthetic model",
        "backend.stdout.bin": b"",
        "backend.stderr.bin": b"",
    }
    if not qemu:
        files.update({"run.resc": b"synthetic script", "renode.config": b""})
    if uart is not None:
        files["uart.bin"] = uart
    if flash:
        del files["firmware.elf"]
        files.update(
            {
                "flash-input.bin": b"\xff" * (4 * 1024 * 1024),
                "flash-work.bin": b"\xff" * (4 * 1024 * 1024),
                "esp32c3-rom.bin": b"synthetic ROM",
                "efuse-initial.bin": bytes(1024),
                "efuse-work.bin": bytes(1024),
                "backend.stderr.bin": b"synthetic model limit\n" * 2,
            }
        )
    profile = "esp32c3-ram-uart-v1" if qemu else "nrf52840-uart-v1"
    plan = {
        **BOUNDARIES,
        "schema_version": "embedded-sim-runner.qemu-plan.v1"
        if qemu
        else "embedded-sim-runner.plan.v1",
        "profile": profile,
        "runtime_lock": {"sha256": digest(files["runtime-lock.json"])},
        "firmware": {
            "sha256": digest(
                files["flash-input.bin" if flash else "firmware.elf" if qemu else "firmware.bin"]
            )
        },
        "model_sha256": digest(files["model.json" if qemu else "model.repl"]),
    }
    if flash:
        profile = "esp32c3-idf-flash-v1"
        plan.update(
            schema_version="embedded-sim-runner.qemu-flash-plan.v1",
            profile=profile,
            rom_sha256=digest(files["esp32c3-rom.bin"]),
            efuse_initial_sha256=digest(files["efuse-initial.bin"]),
        )
    files["plan.json"] = json.dumps(plan).encode()
    artifacts = {}
    for name, data in files.items():
        (root / name).write_bytes(data)
        artifacts[name] = {"path": "Z:/ignored/" + name, "bytes": len(data), "sha256": digest(data)}
    report = {
        **BOUNDARIES,
        "schema_version": "embedded-sim-runner.qemu-report.v1"
        if qemu
        else "embedded-sim-runner.report.v1",
        "profile": profile,
        "ok": passed,
        "status": "passed" if passed else "failed",
        "artifacts": artifacts,
        "plan_sha256": digest(files["plan.json"]),
        "runtime_lock_sha256": digest(files["runtime-lock.json"]),
        "host_started_utc": "2026-10-21T01:00:00Z",
        "host_finished_utc": "2026-10-21T01:00:04Z",
        "virtual_time": {"domain": "synthetic", "elapsed_ns": None},
        "input_hashes_current": True,
        "process": {
            "exit_code": 0,
            "error": None,
            "forced_termination": False,
            "cleanup": {
                "process_exited": True,
                "job_active_processes": 0,
                "capture_threads_stopped": True,
            },
        },
        "errors": [] if passed else [{"code": "MODEL_COVERAGE_FAILED"}],
    }
    if flash:
        report.update(
            schema_version="embedded-sim-runner.qemu-flash-report.v1",
            status="passed_with_model_limits" if passed else "failed",
            assertions={
                "model_diagnostics": [
                    {"message": "synthetic model limit", "count": 2, "meaning": "synthetic"}
                ]
            }
            if passed
            else None,
            model_coverage_complete=False,
            security_features_verified=False,
        )
    path = root / "report.json"
    path.write_text(json.dumps(report))
    return path


@pytest.mark.parametrize("passed", [True, False])
def test_flash_storage_exceeds_old_budget_and_keeps_limited_or_failed_verdict(
    tmp_path, monkeypatch, passed
):
    monkeypatch.setattr(
        "subprocess.Popen", lambda *a, **kw: pytest.fail("offline Flash import spawned")
    )
    path = evidence(tmp_path / "native", flash=True, passed=passed)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["extra_input_bytes"] > 8 * 1024 * 1024
    assert source["capture_outcome"] == ("succeeded_with_model_limits" if passed else "failed")
    assert doc["status"] == "correlated_with_warnings"
    assert source["model_coverage_complete"] is source["security_features_verified"] is False
    assert source["model_diagnostics"] == (
        []
        if not passed
        else [{"message": "synthetic model limit", "count": 2, "meaning": "synthetic"}]
    )
    if passed:
        from embedded_trace.query import inspect, query
        from embedded_trace.report import report as render

        timeline = tmp_path / "timeline.json"
        timeline.write_text(json.dumps(doc))
        markdown = tmp_path / "report.md"
        result = render(timeline, digest(timeline.read_bytes()), markdown)
        assert result["capture_outcomes"] == {"sim": "succeeded_with_model_limits"}
        text = markdown.read_text()
        assert "synthetic model limit" in text and "passed_with_model_limits" in text
        assert '"model_coverage_complete": false' in text
        for value in (
            query(timeline, digest(timeline.read_bytes()), contains="HEARTBEAT"),
            inspect(timeline, digest(timeline.read_bytes())),
        ):
            assert value["capture_outcomes"] == {"sim": "succeeded_with_model_limits"}
            assert (
                value["simulation_sources"]["sim"]["model_diagnostics"]
                == source["model_diagnostics"]
            )


@pytest.mark.parametrize("mutation", ["status", "diagnostics", "coverage", "security", "warning"])
def test_flash_timeline_cannot_flatten_native_model_limitations(tmp_path, mutation):
    doc = correlate(spec(evidence(tmp_path / "native", flash=True)))
    source = doc["sources"][0]
    if mutation == "status":
        source.update(capture_outcome="succeeded", recorded_status="passed", warnings={})
        doc["status"] = "correlated"
    if mutation == "diagnostics":
        source["model_diagnostics"] = []
    if mutation == "coverage":
        source["model_coverage_complete"] = True
    if mutation == "security":
        source["security_features_verified"] = True
    if mutation == "warning":
        source["warnings"] = {}
        doc["status"] = "correlated"
    with pytest.raises(TraceError):
        validate(doc)


def test_flash_saved_diagnostic_counts_are_bound_to_raw_stderr(tmp_path):
    path = evidence(tmp_path / "native", flash=True)
    doc = json.loads(path.read_bytes())
    doc["assertions"]["model_diagnostics"][0]["count"] = 3
    path.write_text(json.dumps(doc))
    with pytest.raises(TraceError, match="diagnostic count differs"):
        correlate(spec(path))


def spec(path):
    result = path.parent.parent / "input.json"
    result.write_text(
        json.dumps(
            {
                "schema_version": "embedded-trace.input.v1",
                "sources": [
                    {
                        "id": "sim",
                        "format": "sim-runner-report",
                        "path": path.parent.name + "/report.json",
                        "sha256": digest(path.read_bytes()),
                        "clock_domain": "sim-c3",
                    }
                ],
            }
        )
    )
    return result


@pytest.mark.parametrize("qemu", [True, False])
@pytest.mark.parametrize("passed", [True, False])
def test_saved_native_verdict_and_uart_are_distinct_from_import_success(
    tmp_path, monkeypatch, qemu, passed
):
    monkeypatch.setattr(
        "subprocess.Popen", lambda *a, **kw: pytest.fail("offline import spawned a process")
    )
    path = evidence(tmp_path / "native", qemu=qemu, passed=passed)
    doc = correlate(spec(path))
    validate(doc)
    jsonschema.validate(
        doc,
        json.loads((Path(__file__).parents[1] / "schemas/timeline.v1.schema.json").read_bytes()),
    )
    source = doc["sources"][0]
    assert source["capture_outcome"] == ("succeeded" if passed else "failed")
    assert source["execution_kind"] == "simulation" and source["physical_board_verified"] is False
    assert (
        source["native_summary_verified"] is False
        and source["native_assertions_reexecuted"] is False
    )
    lines = [event for event in doc["events"] if event["kind"] == "line"]
    assert (
        b"".join(base64.b64decode(e["payload"]["raw_base64"]) for e in lines)
        == (path.parent / "uart.bin").read_bytes()
    )
    assert all(
        e["time"] == source["host_window"] and e["stream"] == "simulation.uart" for e in lines
    )
    assert all(e["elapsed_ms"] == {"first": None, "last": None} for e in lines)


def test_event_budget_rejects_excessive_simulation_lines(tmp_path):
    raw = b"a\r\n" * 50000 + b"\xfflast"
    path = evidence(tmp_path / "native", passed=False, uart=raw)
    with pytest.raises(TraceError, match="too many"):
        correlate(spec(path))


def test_chunked_uart_recovers_exact_file_spans(tmp_path):
    raw = (b"a" * 1000 + b"\r\n") * 150 + b"\xfflast"
    path = evidence(tmp_path / "native", passed=False, uart=raw)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    lines = sorted(
        (e for e in doc["events"] if e["kind"] == "line"), key=lambda e: e["source_ordinal"]
    )
    for event in lines:
        restored = b""
        for span in event["payload"]["segments"]:
            record = source["saved_records"][span["record_index"] - 1]
            start = record["byte_start"]
            restored += raw[start + span["payload_byte_start"] : start + span["payload_byte_end"]]
        assert restored == base64.b64decode(event["payload"]["raw_base64"])
    assert lines[-1]["payload"]["complete"] is False and lines[-1]["payload"]["utf8_valid"] is False


@pytest.mark.parametrize(
    "name", ["uart.bin", "plan.json", "runtime-lock.json", "firmware.elf", "model.json"]
)
def test_changed_adjacent_evidence_is_rejected(tmp_path, name):
    path = evidence(tmp_path / "native")
    selected = spec(path)
    (path.parent / name).write_bytes(b"changed")
    with pytest.raises(TraceError, match="SHA-256"):
        correlate(selected)


@pytest.mark.parametrize(
    "field", ["hardware_access", "physical_board_verified", "physical_firmware_identity_verified"]
)
def test_physical_claims_in_simulation_are_rejected(tmp_path, field):
    path = evidence(tmp_path / "native")
    report = json.loads(path.read_bytes())
    report[field] = True
    path.write_text(json.dumps(report))
    with pytest.raises(TraceError, match="boundary"):
        correlate(spec(path))


def test_missing_uart_on_failed_run_is_preserved(tmp_path):
    path = evidence(tmp_path / "native", passed=False, uart=None)
    doc = correlate(spec(path))
    validate(doc)
    assert doc["sources"][0]["capture_outcome"] == "failed" and doc["event_count"] == 1


def test_simulation_and_device_sources_cannot_share_clock_domain(tmp_path):
    path = evidence(tmp_path / "native")
    selected = spec(path)
    baud = tmp_path / "baud.jsonl"
    baud.write_text(
        '{"ts":"2026-10-21T01:00:00Z","type":"run_started"}\n{"ts":"2026-10-21T01:00:04Z","type":"run_finished","ok":true}\n'
    )
    value = json.loads(selected.read_bytes())
    value["sources"].append(
        {
            "id": "serial",
            "format": "baud-jsonl",
            "path": "baud.jsonl",
            "sha256": digest(baud.read_bytes()),
            "clock_domain": "sim-c3",
        }
    )
    selected.write_text(json.dumps(value))
    with pytest.raises(TraceError, match="distinct clock"):
        correlate(selected)
    value["sources"][-1]["clock_domain"] = "device-host"
    selected.write_text(json.dumps(value))
    validate(correlate(selected))
    changed = correlate(selected)
    changed["sources"][1]["extra_input_bytes"] = -1
    with pytest.raises(TraceError):
        validate(changed)


def test_timeline_cannot_relabel_simulation_lines(tmp_path):
    doc = correlate(spec(evidence(tmp_path / "native")))
    for field, value in (("physical_board_verified", True), ("native_assertions_reexecuted", True)):
        changed = copy.deepcopy(doc)
        changed["sources"][0][field] = value
        with pytest.raises(TraceError):
            validate(changed)


@pytest.mark.parametrize("mutation", ["verdict", "container", "uart", "window"])
def test_rehashed_timeline_cannot_change_simulation_semantics(tmp_path, mutation):
    doc = correlate(spec(evidence(tmp_path / "native")))
    source = doc["sources"][0]
    if mutation == "verdict":
        source["recorded_status"] = "failed"
    if mutation == "container":
        source["saved_records"][1]["byte_start"] = 1
    if mutation == "uart":
        source["evidence_inputs"]["uart.bin"]["sha256"] = "0" * 64
    if mutation == "window":
        event = next(e for e in doc["events"] if e["kind"] == "line")
        event["time"] = dict(event["time"], first_recorded_at="2026-10-21T01:00:01Z")
    with pytest.raises(TraceError):
        validate(doc)
