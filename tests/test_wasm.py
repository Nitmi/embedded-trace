"""Synthetic WASM evidence: encoded strings and unknown outcomes remain explicit."""

import copy
import json
import shutil

import pytest
from test_simulation import spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import BOUNDARIES, WASM_FIELDS, WASM_LIMITS, WASM_PROFILE
from embedded_trace.timeline import correlate


def evidence(root, outcome="passed"):
    root.mkdir()
    uart = b"READY\r\nBUILD synthetic\r\nHEARTBEAT 00000001\r\n"
    seen = {
        "schema_version": "embedded-sim-runner.esp-wasm-host.v1",
        "node_version": "24.15.0",
        "chip": "esp32c3",
        "harts": 1,
        "xtensa": False,
        "batches": 1,
        "requested_instruction_upper_bound": 10000,
        "cycle_counter": "160",
        "cycles_per_us_claim": 160,
        "stop_reason": "instruction_budget" if outcome == "budget" else "guest_restart_requested",
        "uart_utf8_bytes": len(uart),
        "uart_representation": "ascii_subset_of_wasm_strings_encoded_utf8",
        "restart_performed": False,
        "physical_bridges": [],
    }
    files = {
        "component/" + n: b"synthetic " + n.encode()
        for n in ("esp_emu.js", "package.json", "LICENSE")
    }
    # Exceeds the old 8 MiB aggregate limit, but stays within the bounded Flash budget.
    files["component/esp_emu_bg.wasm"] = b"x" * 4904474
    files.update(
        {
            "flash-input.bin": b"\xff" * (4 * 1024 * 1024),
            "runner.mjs": b"synthetic host, never executed",
            "uart.bin": uart,
            "backend.stdout.bin": json.dumps(seen).encode(),
            "backend.stderr.bin": b"",
        }
    )
    identity = {
        "backend": "espressif-esp-emulator-wasm",
        "version": "0.50.0",
        "archive_sha256": "a" * 64,
        "node_version": "24.15.0",
        "files": {
            "www/pkg/" + n.split("/")[1]: digest(b)
            for n, b in files.items()
            if n.startswith("component/")
        },
    }
    files["model.json"] = json.dumps(identity).encode()
    files["runtime-lock.json"] = json.dumps(
        {
            **identity,
            "schema_version": "embedded-sim-runner.esp-wasm-runtime.v1",
            "node": {"version": "24.15.0"},
        }
    ).encode()
    initial = "fresh_instance_private_flash_builtin_rom_and_opaque_default_efuse"
    plan = {
        **BOUNDARIES,
        "schema_version": "embedded-sim-runner.esp-wasm-plan.v1",
        "profile": WASM_PROFILE,
        "backend": identity["backend"],
        "backend_version": "0.50.0",
        "runtime_lock": {"sha256": digest(files["runtime-lock.json"])},
        "firmware": {"sha256": digest(files["flash-input.bin"])},
        "model_sha256": digest(files["model.json"]),
        "host_script_sha256": digest(files["runner.mjs"]),
        "initial_state": initial,
        "physical_bridges": [],
        "retries": 0,
        "instruction_budget": 10000,
    }
    files["plan.json"] = json.dumps(plan).encode()
    report = {
        **BOUNDARIES,
        "schema_version": "embedded-sim-runner.esp-wasm-report.v1",
        "profile": WASM_PROFILE,
        "backend": identity["backend"],
        "backend_version": "0.50.0",
        "runtime_archive_sha256": "a" * 64,
        "initial_state": initial,
        "ok": outcome == "passed",
        "status": "passed_with_model_limits" if outcome == "passed" else "failed",
        "model_limits": WASM_LIMITS,
        "virtual_time": {
            "domain": "esp_emulator_unmeasured_device_clock",
            "elapsed_ns": None,
            "budget_enforced": False,
        },
        "uart_timestamps_available": False,
        "raw_uart_bytes_verified": False,
        "uart_representation": seen["uart_representation"],
        "model_coverage_complete": False,
        "physical_timing_verified": False,
        "security_features_verified": False,
        "runtime_observation": None if outcome == "timeout" else seen,
        "assertions": None if outcome != "passed" else {"ready": True},
        "errors": []
        if outcome == "passed"
        else [
            {
                "code": "TIMEOUT" if outcome == "timeout" else "INSTRUCTION_BUDGET_EXCEEDED",
                "message": "synthetic native failure",
            }
        ],
        "plan_sha256": digest(files["plan.json"]),
        "runtime_lock_sha256": digest(files["runtime-lock.json"]),
        "host_started_utc": "2026-10-22T01:00:00Z",
        "host_finished_utc": "2026-10-22T01:00:01Z",
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
        "artifacts": {
            n: {"path": "Z:/ignored/" + n, "bytes": len(b), "sha256": digest(b)}
            for n, b in files.items()
        },
    }
    for n, b in files.items():
        p = root / n
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(b)
    path = root / "report.json"
    path.write_text(json.dumps(report))
    return path


@pytest.mark.parametrize("outcome", ["passed", "budget", "timeout"])
def test_offline_views_keep_string_origin_limits_stop_and_null(tmp_path, monkeypatch, outcome):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline process launch"))
    path = evidence(tmp_path / "native", outcome)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["extra_input_bytes"] > 8 * 1024 * 1024
    assert source["capture_outcome"] == (
        "succeeded_with_model_limits" if outcome == "passed" else "failed"
    )
    assert source["raw_uart_bytes_verified"] is False
    assert source["virtual_time"]["elapsed_ns"] is None
    assert (source["runtime_observation"] is None) is (outcome == "timeout")
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    shutil.rmtree(path.parent)
    hashed = digest(timeline.read_bytes())
    for result in (
        inspect(timeline, hashed),
        query(timeline, hashed, contains="HEARTBEAT", limit=1),
        render(timeline, hashed, tmp_path / "report.md", contains="HEARTBEAT"),
    ):
        assert all(result["simulation_sources"]["sim"][k] == source[k] for k in WASM_FIELDS)
    assert "ascii_subset_of_wasm_strings_encoded_utf8" in (tmp_path / "report.md").read_text()


@pytest.mark.parametrize(
    "key,value",
    [
        ("raw_uart_bytes_verified", True),
        ("model_limits", []),
        ("native_errors", []),
        ("native_assertions", {}),
        ("runtime_observation", {}),
        ("initial_state", "known efuse"),
        ("uart_representation", "raw UART"),
        ("physical_timing_verified", True),
    ],
)
def test_timeline_cannot_drop_or_relabel_wasm_context(tmp_path, key, value):
    doc = correlate(spec(evidence(tmp_path / "native", "budget")))
    changed = copy.deepcopy(doc)
    changed["sources"][0][key] = value
    with pytest.raises(TraceError):
        validate(changed)


@pytest.mark.parametrize(
    "mutation",
    ["path", "clock", "unqualified", "component", "stdout", "restart", "nominal-clock", "unicode"],
)
def test_import_rejects_inconsistent_saved_evidence(tmp_path, mutation):
    path = evidence(tmp_path / "native")
    doc = json.loads(path.read_bytes())
    if mutation == "path":
        doc["artifacts"]["component/../escape"] = doc["artifacts"]["component/LICENSE"]
    elif mutation == "clock":
        doc["virtual_time"]["budget_enforced"] = 0
    elif mutation == "unqualified":
        doc["status"] = "passed"
    elif mutation == "component":
        (path.parent / "component/LICENSE").write_bytes(b"drift")
    elif mutation == "stdout":
        doc["runtime_observation"]["cycle_counter"] = "321"
    elif mutation == "restart":
        doc["runtime_observation"]["restart_performed"] = True
    elif mutation == "nominal-clock":
        doc["runtime_observation"]["cycles_per_us_claim"] = True
    elif mutation == "unicode":
        raw = b"\xc3\xa9" * (len((path.parent / "uart.bin").read_bytes()) // 2)
        (path.parent / "uart.bin").write_bytes(raw)
        doc["artifacts"]["uart.bin"].update(bytes=len(raw), sha256=digest(raw))
    path.write_text(json.dumps(doc))
    with pytest.raises(TraceError):
        correlate(spec(path))
