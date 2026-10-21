"""Offline sim-runner evidence adapter. Never load/execute the simulator package."""

from __future__ import annotations

from pathlib import Path

from .clock import observed, unix_ns
from .common import (
    MAX_RECORD_BYTES,
    MAX_SOURCE_BYTES,
    digest,
    integer,
    parse_json,
    read_file,
    require,
)
from .framing import Framer

FORMAT = "sim-runner-report"
BOUNDARIES = {
    "execution_kind": "simulation",
    "hardware_access": False,
    "physical_board_verified": False,
    "physical_firmware_identity_verified": False,
}


def import_report(raw: bytes, path: Path, source: dict, events: list[dict]) -> int:
    require(
        len(raw) <= MAX_RECORD_BYTES, "simulation report exceeds record limit", "LIMIT_EXCEEDED"
    )
    report = parse_json(raw)
    qemu = report.get("schema_version") == "embedded-sim-runner.qemu-report.v1"
    require(
        qemu or report.get("schema_version") == "embedded-sim-runner.report.v1",
        "unsupported simulation report",
    )
    for key, value in BOUNDARIES.items():
        require(
            type(report.get(key)) is type(value) and report[key] == value,
            "invalid simulation boundary",
        )
    profile = "esp32c3-ram-uart-v1" if qemu else "nrf52840-uart-v1"
    require(report.get("profile") == profile, "unsupported simulation profile")
    require(
        report.get("status") in ("passed", "failed")
        and report.get("ok") is (report["status"] == "passed"),
        "simulation verdict mismatch",
    )
    required = (
        {"plan.json", "runtime-lock.json", "firmware.elf", "model.json"}
        if qemu
        else {
            "plan.json",
            "runtime-lock.json",
            "firmware.bin",
            "model.repl",
            "run.resc",
            "renode.config",
        }
    )
    artifacts = report.get("artifacts")
    require(
        isinstance(artifacts, dict)
        and required
        <= set(artifacts)
        <= required | {"uart.bin", "backend.stdout.bin", "backend.stderr.bin"},
        "invalid simulation artifact inventory",
    )
    loaded = {}
    refs = {}
    total = 0
    for name, record in artifacts.items():
        require(isinstance(record, dict), "invalid artifact record")
        # Never follow recorded absolute paths; only the adjacent fixed filenames.
        data, ref = read_file(path.parent / name, MAX_SOURCE_BYTES, record.get("sha256"))
        require(
            len(data) == integer(record.get("bytes"), "artifact bytes", 0, MAX_SOURCE_BYTES),
            "artifact size differs",
        )
        total += len(data)
        require(
            total + len(raw) <= MAX_SOURCE_BYTES,
            "simulation evidence exceeds source byte budget",
            "LIMIT_EXCEEDED",
        )
        loaded[name], refs[name] = data, ref
    plan = parse_json(loaded["plan.json"])
    require(
        digest(loaded["plan.json"]) == report.get("plan_sha256"), "simulation plan binding differs"
    )
    require(
        digest(loaded["runtime-lock.json"])
        == report.get("runtime_lock_sha256")
        == plan["runtime_lock"]["sha256"],
        "runtime binding differs",
    )
    require(
        digest(loaded["firmware.elf" if qemu else "firmware.bin"]) == plan["firmware"]["sha256"],
        "firmware binding differs",
    )
    require(
        digest(loaded["model.json" if qemu else "model.repl"]) == plan["model_sha256"],
        "model binding differs",
    )
    require(
        plan.get("profile") == profile
        and plan.get("schema_version")
        == ("embedded-sim-runner.qemu-plan.v1" if qemu else "embedded-sim-runner.plan.v1"),
        "simulation plan profile differs",
    )
    for key, value in BOUNDARIES.items():
        require(
            type(plan.get(key)) is type(value) and plan[key] == value,
            "invalid plan simulation boundary",
        )
    first = {
        "index": 1,
        "timestamp": report.get("host_started_utc"),
        "ns": unix_ns(report.get("host_started_utc")),
    }
    last = {
        "index": 1,
        "timestamp": report.get("host_finished_utc"),
        "ns": unix_ns(report.get("host_finished_utc")),
    }
    window = observed(first, last)
    if last["ns"] < first["ns"]:
        source["warnings"]["wall_clock_regressions"] = 1
    if report["ok"]:
        process = report.get("process", {})
        require(
            process.get("exit_code") == 0
            and process.get("error") is None
            and process.get("forced_termination") is False,
            "passed simulation has failed process",
        )
        require(
            process.get("cleanup")
            == {"process_exited": True, "job_active_processes": 0, "capture_threads_stopped": True},
            "passed simulation cleanup incomplete",
        )
        require(
            report.get("input_hashes_current") is True
            and report.get("errors") == []
            and "uart.bin" in loaded,
            "passed simulation lacks complete evidence",
        )
    source.update(
        execution_kind="simulation",
        physical_board_verified=False,
        capture_outcome="succeeded" if report["ok"] else "failed",
        time_semantics="simulation_run_host_window_not_uart_event_time",
        host_window=window,
        evidence_inputs=refs,
        extra_input_bytes=total,
        recorded_status=report["status"],
        native_assertions_reexecuted=False,
        virtual_time=report.get("virtual_time"),
        profile=profile,
        saved_records=[
            {"index": 1, "artifact": "selected_report", "byte_start": 0, "byte_end": len(raw)}
        ],
    )
    source["integrity"].update(
        saved_artifacts_hash_verified=True, finish_payload_hash_verified=None
    )
    framer = Framer(source, events)
    framer.metadata(report, last)
    uart = loaded.get("uart.bin")
    count = 1
    if uart is not None:
        # File chunks are explicitly synthetic containers, not native UART records.
        for offset in range(0, max(1, len(uart)), 65536):
            count += 1
            chunk = uart[offset : offset + 65536]
            source["saved_records"].append(
                {
                    "index": count,
                    "artifact": "uart.bin",
                    "byte_start": offset,
                    "byte_end": offset + len(chunk),
                }
            )
            ctx = {**first, "index": count}
            if chunk:
                framer.feed("simulation.uart", "saved_uart", chunk, ctx)
            else:
                framer.metadata({"artifact": "uart.bin", "bytes": 0}, {**last, "index": count})
        framer.finish()
    for event in events:
        if event.get("source_id") == source["id"] and event["kind"] == "line":
            event["time"] = dict(window)
    source["record_count"] = count
    source["payload_bytes"] = len(uart or b"")
    return total
