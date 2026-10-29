"""Offline sim-runner evidence adapter. Never load/execute the simulator package."""

from __future__ import annotations

import base64
import copy
import json
import re
from pathlib import Path

from .adapters import decode_base64
from .clock import observed, unix_ns
from .common import (
    MAX_FLASH_SOURCE_BYTES,
    MAX_RECORD_BYTES,
    MAX_SOURCE_BYTES,
    digest,
    integer,
    parse_json,
    read_file,
    require,
    text,
)
from .framing import Framer

FORMAT = "sim-runner-report"
SENSOR_PROFILE = "nrf52840-i2c-sensor-v1"
SENSOR_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "sensor_accuracy_verified": False,
    "i2c_electrical_behavior_verified": False,
    "sensor_observation_semantics": "paused_model_property_and_register_snapshot_not_measurement",
    "sensor_sample_semantics": "guest_TWI0_register0_signed_byte_not_calibrated_temperature",
    "timer_observation_semantics": "guest_250kHz_TIMER0_IRQ_capture_not_host_time",
}
SENSOR_FIELDS = (
    *SENSOR_LABELS,
    "fault_scenario",
    "fault_request",
    "sensor_evidence",
    "sensor_observation_spans",
    "native_errors",
)
WASM_PROFILE = "esp32c3-wasm-flash-v1"
WASM_COMPONENTS = {
    "component/" + n for n in ("esp_emu.js", "esp_emu_bg.wasm", "package.json", "LICENSE")
}
WASM_LIMITS = [
    "experimental_binary_only_core_not_independently_source_verified",
    "uart_api_returns_strings_original_uart_byte_fidelity_not_established",
    "embedded_rom_and_efuse_defaults_not_independently_dumped",
    "cycle_counter_and_cycles_per_us_are_model_claims_not_measured_timing",
    "no_radio_network_electrical_or_complete_chip_coverage",
]
WASM_FIELDS = (
    "backend",
    "backend_version",
    "runtime_archive_sha256",
    "virtual_time",
    "uart_timestamps_available",
    "uart_representation",
    "raw_uart_bytes_verified",
    "model_coverage_complete",
    "physical_timing_verified",
    "security_features_verified",
    "initial_state",
    "model_limits",
    "runtime_observation",
    "native_errors",
    "native_assertions",
)
FLASH_PROFILE = "esp32c3-idf-flash-v1"
S3_PROFILE = "esp32s3-idf-flash-v1"
FLASH_PROFILES = (FLASH_PROFILE, S3_PROFILE)
S3_FIELDS = (
    "backend",
    "backend_version",
    "runtime_archive_sha256",
    "virtual_time",
    "app_core_markers",
)
GPIO_PROFILE = "nrf52840-gpio-timer-v1"
FAULT_PROFILE = "nrf52840-gpio-timer-fault-v1"
FAULTS = ("none", "gpio-stuck-low", "gpio-stuck-high", "timer-stop", "timer-irq-mask")
FAULT_SCOPE = "fixed_paused_model_input_not_physical_fault_or_root_cause_proof"
FAULT_FIELDS = ("fault_scenario", "fault_scope", "fault_request", "fault_evidence", "native_errors")
GPIO_LABELS = {
    "gpio_observation_semantics": "paused_model_register_snapshot_not_electrical_waveform",
    "timer_observation_semantics": "guest_reported_250kHz_capture_in_TIMER0_IRQ_not_host_time",
}
GPIO_FIELDS = (
    "model_coverage_complete",
    "physical_timing_verified",
    *GPIO_LABELS,
    "gpio_evidence",
    "gpio_observation_spans",
)
OUTCOMES = {
    "passed": "succeeded",
    "passed_with_model_limits": "succeeded_with_model_limits",
    "failed": "failed",
}
BOUNDARIES = {
    "execution_kind": "simulation",
    "hardware_access": False,
    "physical_board_verified": False,
    "physical_firmware_identity_verified": False,
}


def wasm_summary(report: dict) -> dict:
    """Keep native declarations, including unknown outcomes; never rerun firmware policy."""
    require(
        report.get("schema_version") == "embedded-sim-runner.esp-wasm-report.v1"
        and report.get("backend") == "espressif-esp-emulator-wasm"
        and report.get("backend_version") == "0.50.0"
        and report.get("status") in ("failed", "passed_with_model_limits")
        and report.get("model_limits") == WASM_LIMITS
        and report.get("initial_state")
        == "fresh_instance_private_flash_builtin_rom_and_opaque_default_efuse"
        and report.get("uart_representation") == "ascii_subset_of_wasm_strings_encoded_utf8"
        and all(
            report.get(k) is False
            for k in (
                "uart_timestamps_available",
                "raw_uart_bytes_verified",
                "model_coverage_complete",
                "physical_timing_verified",
                "security_features_verified",
            )
        ),
        "invalid WASM identity/qualification/representation",
    )
    clock = report.get("virtual_time")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "elapsed_ns", "budget_enforced"}
        and clock["domain"] == "esp_emulator_unmeasured_device_clock"
        and clock["elapsed_ns"] is None
        and clock["budget_enforced"] is False,
        "invalid WASM unmeasured clock",
    )
    require(
        re.fullmatch(
            r"[0-9a-f]{64}", text(report.get("runtime_archive_sha256"), "WASM archive hash", 64)
        )
        is not None,
        "invalid WASM archive hash",
    )
    seen = report.get("runtime_observation")
    require(seen is None or isinstance(seen, dict), "invalid WASM observation")
    if seen is not None:
        require(
            set(seen)
            == {
                "schema_version",
                "node_version",
                "chip",
                "harts",
                "xtensa",
                "batches",
                "requested_instruction_upper_bound",
                "cycle_counter",
                "cycles_per_us_claim",
                "stop_reason",
                "uart_utf8_bytes",
                "uart_representation",
                "restart_performed",
                "physical_bridges",
            },
            "invalid WASM host fields",
        )
        require(
            seen["schema_version"] == "embedded-sim-runner.esp-wasm-host.v1"
            and seen["node_version"] == "24.15.0"
            and seen["chip"] == "esp32c3"
            and type(seen["harts"]) is int
            and seen["harts"] == 1
            and seen["xtensa"] is False
            and seen["restart_performed"] is False
            and seen["physical_bridges"] == []
            and seen["stop_reason"] in ("guest_restart_requested", "instruction_budget")
            and seen["uart_representation"] == report["uart_representation"],
            "invalid WASM host identity/stop/bridge declaration",
        )
        batches = integer(seen["batches"], "WASM batches", 1, 10000)
        require(
            integer(seen["requested_instruction_upper_bound"], "requested instruction bound")
            == batches * 10000,
            "invalid WASM instruction upper bound",
        )
        require(
            re.fullmatch(r"[0-9]{1,20}", text(seen["cycle_counter"], "model counter", 20))
            is not None,
            "invalid WASM model counter",
        )
        require(
            type(seen["cycles_per_us_claim"]) is int and seen["cycles_per_us_claim"] == 160,
            "invalid WASM model clock claim",
        )
        integer(seen["uart_utf8_bytes"], "encoded UART bytes", 0, MAX_SOURCE_BYTES)
    assertions, errors = report.get("assertions"), report.get("errors")
    require(assertions is None or isinstance(assertions, dict), "invalid WASM assertions")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid WASM errors")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"code", "message"}, "invalid WASM error")
        text(error["code"], "error code", 128)
        text(error["message"], "error message", 2048)
    require(
        not report["ok"] or (seen is not None and assertions is not None),
        "passing WASM lacks native declarations",
    )
    return {
        k: copy.deepcopy(report[k])
        for k in WASM_FIELDS
        if k not in ("native_errors", "native_assertions")
    } | {"native_errors": copy.deepcopy(errors), "native_assertions": copy.deepcopy(assertions)}


def wasm_binding(report, plan, loaded, source):
    summary = wasm_summary(report)
    runtime, model = (parse_json(loaded[n]) for n in ("runtime-lock.json", "model.json"))
    require(
        plan.get("backend") == runtime.get("backend") == model.get("backend") == summary["backend"]
        and plan.get("backend_version")
        == runtime.get("version")
        == model.get("version")
        == summary["backend_version"]
        and runtime.get("schema_version") == "embedded-sim-runner.esp-wasm-runtime.v1"
        and runtime.get("archive_sha256")
        == model.get("archive_sha256")
        == summary["runtime_archive_sha256"]
        and runtime.get("files") == model.get("files")
        and runtime.get("node", {}).get("version") == model.get("node_version") == "24.15.0"
        and plan.get("initial_state") == summary["initial_state"]
        and plan.get("physical_bridges") == []
        and plan.get("retries") == 0
        and digest(loaded["runner.mjs"]) == plan.get("host_script_sha256")
        and len(loaded["flash-input.bin"]) == 4 * 1024 * 1024,
        "WASM runtime/model/initial-state binding differs",
    )
    files = runtime.get("files")
    require(isinstance(files, dict), "invalid WASM runtime files")
    for name in WASM_COMPONENTS:
        require(
            digest(loaded[name]) == files.get("www/pkg/" + name.split("/")[1]),
            "WASM saved component binding differs",
        )
    budget = integer(plan.get("instruction_budget"), "instruction budget", 10000, 100000000)
    require(budget % 10000 == 0, "invalid WASM instruction budget")
    seen = summary["runtime_observation"]
    if seen is not None:
        uart = loaded.get("uart.bin", b"")
        require(
            uart.isascii()
            and len(uart) == seen["uart_utf8_bytes"]
            and seen["requested_instruction_upper_bound"] <= budget
            and (
                seen["stop_reason"] != "instruction_budget"
                or seen["requested_instruction_upper_bound"] == budget
            )
            and json.dumps(parse_json(loaded.get("backend.stdout.bin", b"")), sort_keys=True)
            == json.dumps(seen, sort_keys=True),
            "WASM saved host summary/encoded UART differs",
        )
    source.update(summary)
    source["warnings"].update(model_coverage_incomplete=1, uart_byte_fidelity_unverified=1)


def model_limits(report: dict) -> dict:
    """Retain bounded native declarations, without rerunning firmware assertions."""
    require(
        report.get("model_coverage_complete") is False
        and report.get("security_features_verified") is False,
        "invalid Flash coverage claim",
    )
    assertions = report.get("assertions")
    diagnostics = assertions.get("model_diagnostics") if isinstance(assertions, dict) else []
    require(isinstance(diagnostics, list) and len(diagnostics) <= 6, "invalid model diagnostics")
    seen = set()
    for row in diagnostics:
        require(
            isinstance(row, dict) and set(row) == {"message", "count", "meaning"},
            "invalid model diagnostic",
        )
        message = text(row["message"], "diagnostic message", 256)
        text(row["meaning"], "diagnostic meaning", 256)
        integer(row["count"], "diagnostic count", 1, 256)
        require(message and message not in seen, "duplicate/empty model diagnostic")
        seen.add(message)
    if report["ok"]:
        require(
            (report["status"] == "passed_with_model_limits") is bool(diagnostics),
            "model diagnostic verdict mismatch",
        )
    return {
        "model_diagnostics": diagnostics,
        "model_coverage_complete": False,
        "security_features_verified": False,
    }


def gpio_summary(report: dict) -> dict:
    """Check bounded saved declarations, without evaluating the native test policy."""
    require(
        report.get("model_coverage_complete") is False
        and report.get("physical_timing_verified") is False
        and all(report.get(k) == v for k, v in GPIO_LABELS.items()),
        "invalid GPIO coverage or observation semantics",
    )
    fault = report.get("profile") == FAULT_PROFILE
    assertions = report.get("assertions")
    require(assertions is None or isinstance(assertions, dict), "invalid GPIO assertions")
    require(not report["ok"] or isinstance(assertions, dict), "passing GPIO lacks assertions")
    evidence = {"samples": None, "model_observations": None}
    if assertions is not None:
        for key, maximum, fields in (
            (
                "samples",
                64,
                ("sequence", "input", "output", "loopback", "timer_ticks", "irq_vector"),
            ),
            (
                "model_observations",
                16,
                ("phase", "requested_virtual_ms", "out_register", "in_register")
                + (("timer_counter", "interrupt_enable") if fault else ()),
            ),
        ):
            rows = assertions.get(key)
            if fault:
                maximum = 16 if key == "samples" else 4
            require(isinstance(rows, list) and len(rows) <= maximum, "invalid GPIO evidence rows")
            for row in rows:
                require(
                    isinstance(row, dict) and set(row) == set(fields),
                    "invalid GPIO evidence fields",
                )
                for field in fields:
                    integer(
                        row[field],
                        field,
                        0,
                        1 if field in ("input", "output", "loopback") else 2**32 - 1,
                    )
            evidence[key] = [dict(row) for row in rows]
        if fault:
            require(
                [row["phase"] for row in evidence["model_observations"]] in ([], [0, 1, 2, 3]),
                "invalid fault model observation inventory/order",
            )
    result = {
        "model_coverage_complete": False,
        "physical_timing_verified": False,
        **GPIO_LABELS,
        "gpio_evidence": evidence,
    }
    if fault:
        result.update(fault_summary(report))
    return result


def fault_summary(report: dict) -> dict:
    """Preserve native analysis, including unknown effects, without rerunning policy."""
    scenario = report.get("fault_scenario")
    require(
        scenario in FAULTS and report.get("fault_scope") == FAULT_SCOPE, "invalid fault identity"
    )
    assertions = report.get("assertions")
    if assertions is not None:
        require(
            type(assertions.get("nominal_regression_passed")) is bool, "invalid nominal verdict"
        )
        failure = assertions.get("nominal_failure")
        require(failure is None or isinstance(failure, str), "invalid nominal failure")
        if failure is not None:
            text(failure, "nominal failure", 2048)
        effect = assertions.get("fault")
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == scenario
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "not_requested", "observed", "not_observed"),
            "invalid native fault effect",
        )
        for key in (
            "ready_matches",
            "build_matches",
            "model_timer_nominal",
            "sample_summary_truncated",
        ):
            if key in assertions:
                require(type(assertions[key]) is bool, "invalid fault boolean declaration")
        if "sample_lines_seen" in assertions:
            integer(assertions["sample_lines_seen"], "sample lines", 0, MAX_SOURCE_BYTES)
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid native fault errors")
    for error in errors:
        require(
            isinstance(error, dict) and set(error) == {"code", "message"}, "invalid fault error"
        )
        text(error["code"], "native error code", 128)
        text(error["message"], "native error message", 2048)
    clock = report.get("virtual_time")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 82
        and type(clock["completed"]) is bool,
        "invalid fault virtual time declaration",
    )
    return {
        "fault_scenario": scenario,
        "fault_scope": FAULT_SCOPE,
        "fault_request": {
            "id": scenario,
            "requested_virtual_ms": None if scenario == "none" else 22,
        },
        "fault_evidence": copy.deepcopy(assertions),
        "native_errors": copy.deepcopy(errors),
    }


def s3_summary(report: dict) -> dict:
    """Retain bounded native declarations; CPU/readiness policy remains native."""
    require(
        report.get("schema_version") == "embedded-sim-runner.qemu-s3-flash-report.v1"
        and report.get("backend") == "espressif-qemu-xtensa",
        "invalid S3 backend identity",
    )
    text(report.get("backend_version"), "S3 backend version", 64)
    archive = text(report.get("runtime_archive_sha256"), "S3 archive hash", 64)
    require(re.fullmatch(r"[0-9a-f]{64}", archive) is not None, "invalid S3 archive hash")
    clock = report.get("virtual_time")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "elapsed_ns", "budget_enforced"}
        and clock["domain"] == "qemu_device_clock_unmeasured"
        and clock["elapsed_ns"] is None
        and clock["budget_enforced"] is False,
        "invalid S3 unmeasured clock declaration",
    )
    assertions = report.get("assertions")
    require(assertions is None or isinstance(assertions, dict), "invalid S3 assertions")
    require(not report["ok"] or isinstance(assertions, dict), "passing S3 assertions missing")
    cores = None if assertions is None else assertions.get("app_core_markers")
    require(
        assertions is None or (isinstance(cores, list) and len(cores) <= 2),
        "invalid S3 core marker declarations",
    )
    if cores is not None:
        for core in cores:
            integer(core, "S3 app core marker", 0, 1)
    return {key: copy.deepcopy(report[key]) for key in S3_FIELDS if key != "app_core_markers"} | {
        "app_core_markers": None if cores is None else list(cores)
    }


def gpio_pattern(phase: int, fault=False):
    if fault:
        return (
            rb"(?m)^SIM_FAULT_OBS_"
            + str(phase).encode("ascii")
            + rb"\r?\n([0-9]{1,10})\r?\n([0-9]{1,10})\r?\n([0-9]{1,10})\r?\n([0-9]{1,10})\r?\n"
        )
    return (
        rb"(?m)^SIM_GPIO_OBS_"
        + str(phase).encode("ascii")
        + rb"\r?\n([0-9]{1,10})\r?\n([0-9]{1,10})\r?$"
    )


def gpio_spans(summary: dict, stdout: bytes) -> list:
    spans = []
    fault = "fault_scenario" in summary
    fields = ("out_register", "in_register") + (
        ("timer_counter", "interrupt_enable") if fault else ()
    )
    for row in summary["gpio_evidence"]["model_observations"] or []:
        matches = list(re.finditer(gpio_pattern(row["phase"], fault), stdout))
        require(len(matches) == 1, "GPIO model observation missing/duplicate in stdout")
        match = matches[0]
        require(
            [int(v) for v in match.groups()] == [row[k] for k in fields],
            "GPIO model observation differs from raw stdout",
        )
        raw = match[0]
        spans.append(
            {
                "phase": row["phase"],
                "byte_start": match.start(),
                "byte_end": match.end(),
                "raw_base64": base64.b64encode(raw).decode("ascii"),
                "sha256": digest(raw),
            }
        )
    return spans


def validate_gpio_spans(source: dict) -> None:
    """Validate saved span layout only; query/report never reopen backend stdout."""
    spans = source.get("gpio_observation_spans")
    rows = source["gpio_evidence"]["model_observations"] or []
    require(isinstance(spans, list) and len(spans) == len(rows), "invalid GPIO observation spans")
    cursor = 0
    phases = set()
    fault = source.get("profile") == FAULT_PROFILE
    fields = ("out_register", "in_register") + (
        ("timer_counter", "interrupt_enable") if fault else ()
    )
    for span, row in zip(spans, rows, strict=True):
        require(
            isinstance(span, dict)
            and set(span) == {"phase", "byte_start", "byte_end", "raw_base64", "sha256"}
            and span["phase"] == row["phase"]
            and span["phase"] not in phases,
            "invalid GPIO observation span identity",
        )
        integer(span["phase"], "GPIO phase", 0, 2**32 - 1)
        phases.add(span["phase"])
        ref = source["evidence_inputs"].get("backend.stdout.bin")
        require(isinstance(ref, dict), "GPIO observation stdout reference missing")
        start = integer(span["byte_start"], "GPIO span start", cursor, ref["size_bytes"])
        end = integer(span["byte_end"], "GPIO span end", start + 1, ref["size_bytes"])
        require(end - start <= 128, "GPIO observation span exceeds limit")
        raw = decode_base64(span["raw_base64"])
        match = re.fullmatch(gpio_pattern(row["phase"], fault), raw)
        require(
            len(raw) == end - start
            and digest(raw) == span["sha256"]
            and match is not None
            and [int(v) for v in match.groups()] == [row[k] for k in fields],
            "GPIO observation span content differs",
        )
        cursor = end


def sensor_summary(report: dict) -> dict:
    """Validate recorded structure, not the firmware's signed-temperature regression policy."""
    require(
        report.get("schema_version") == "embedded-sim-runner.sensor-report.v1"
        and report.get("profile") == SENSOR_PROFILE
        and all(
            type(report.get(k)) is type(v) and report[k] == v for k, v in SENSOR_LABELS.items()
        ),
        "invalid sensor identity/qualification",
    )
    fault = report.get("fault_scenario")
    require(
        type(fault) is str and fault in ("none", "temperature-stuck", "temperature-offset"),
        "invalid sensor fault",
    )
    clock = report.get("virtual_time")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 82
        and type(clock["completed"]) is bool,
        "invalid sensor clock",
    )
    evidence = report.get("assertions")
    require(evidence is None or isinstance(evidence, dict), "invalid sensor evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing sensor lacks evidence")
    if evidence is not None:
        require(
            type(evidence.get("nominal_regression_passed")) is bool,
            "invalid sensor nominal verdict",
        )
        failure = evidence.get("nominal_failure")
        require(failure is None or isinstance(failure, str), "invalid sensor failure")
        if failure is not None:
            text(failure, "sensor failure", 2048)
        effect = evidence.get("fault")
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "not_requested", "observed", "not_observed"),
            "invalid sensor effect",
        )
        for key in ("ready_matches", "build_matches", "model_nominal", "sample_summary_truncated"):
            if key in evidence:
                require(type(evidence[key]) is bool, "invalid sensor boolean")
        if "sample_lines_seen" in evidence:
            integer(evidence["sample_lines_seen"], "sensor line count", 0, MAX_SOURCE_BYTES)
        require(
            evidence.get("fault_scenario") == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v
                for k, v in SENSOR_LABELS.items()
            ),
            "sensor assertion context differs",
        )
        samples = evidence.get("samples")
        require(isinstance(samples, list) and len(samples) <= 16, "invalid sensor samples")
        for row in samples:
            require(
                isinstance(row, dict)
                and set(row)
                == {"sequence", "raw_byte", "celsius", "timer_ticks", "irq_vector", "error"},
                "invalid sensor sample fields",
            )
            for field in ("sequence", "timer_ticks", "irq_vector", "error"):
                integer(row[field], field, 0, 2**32 - 1)
            integer(row["raw_byte"], "sensor raw byte", 0, 255)
            integer(row["celsius"], "sensor signed value", -(2**31), 2**31 - 1)
        observations = evidence.get("model_observations")
        require(
            isinstance(observations, list) and len(observations) in (0, 4),
            "invalid sensor observation inventory",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {
                    "phase",
                    "requested_virtual_ms",
                    "temperature_celsius",
                    "i2c_address",
                    "timer_counter",
                    "stdout_offset",
                    "stdout_bytes",
                    "stdout_sha256",
                },
                "invalid sensor observation fields",
            )
            require(
                integer(row["phase"], "sensor phase", 0, 3) == index
                and integer(row["requested_virtual_ms"], "sensor boundary", 20, 80)
                == 20 + 20 * index,
                "sensor observation order/boundary differs",
            )
            integer(row["temperature_celsius"], "sensor property", -128, 127)
            integer(row["i2c_address"], "sensor address", 0, 127)
            integer(row["timer_counter"], "sensor counter", 0, 2**32 - 1)
            integer(row["stdout_offset"], "sensor stdout offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "sensor stdout bytes", 1, 128)
            require(
                re.fullmatch(r"[0-9a-f]{64}", text(row["stdout_sha256"], "sensor span hash", 64))
                is not None,
                "invalid sensor span hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid sensor errors")
    for error in errors:
        require(
            isinstance(error, dict) and set(error) == {"code", "message"}, "invalid sensor error"
        )
        text(error["code"], "sensor error code", 128)
        text(error["message"], "sensor error", 2048)
    return {
        **SENSOR_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "requested_virtual_ms": None if fault == "none" else 22},
        "sensor_evidence": copy.deepcopy(evidence),
        "native_errors": copy.deepcopy(errors),
    }


def validate_sensor_spans(source):
    """Check saved byte-span layout; never reopen an original source or rerun policy."""
    evidence = source["sensor_evidence"]
    rows = [] if evidence is None else evidence["model_observations"]
    spans = source.get("sensor_observation_spans")
    require(isinstance(spans, list) and len(spans) == len(rows), "invalid sensor spans")
    cursor = 0
    for span, row in zip(spans, rows, strict=True):
        require(
            isinstance(span, dict)
            and set(span) == {"phase", "byte_start", "byte_end", "raw_base64", "sha256"}
            and type(span["phase"]) is int
            and span["phase"] == row["phase"],
            "invalid sensor span fields",
        )
        ref = source["evidence_inputs"].get("backend.stdout.bin")
        require(isinstance(ref, dict), "sensor stdout reference missing")
        start = integer(span["byte_start"], "sensor span start", cursor, ref["size_bytes"])
        end = integer(span["byte_end"], "sensor span end", start + 1, ref["size_bytes"])
        require(end - start <= 128, "sensor span exceeds budget")
        raw = decode_base64(span["raw_base64"])
        pattern = (
            rb"SIM_SENSOR_OBS_"
            + str(row["phase"]).encode()
            + rb"\r?\n(-?[0-9]{1,3})\r?\n([0-9]{1,10})\r?\n([0-9]{1,10})\r?\n"
        )
        match = re.fullmatch(pattern, raw)
        require(
            match is not None
            and len(raw) == end - start == row["stdout_bytes"]
            and start == row["stdout_offset"]
            and digest(raw) == span["sha256"] == row["stdout_sha256"]
            and [int(v) for v in match.groups()]
            == [row[k] for k in ("temperature_celsius", "i2c_address", "timer_counter")],
            "sensor span differs from recorded observation",
        )
        cursor = end


def sensor_spans(summary, stdout):
    evidence = summary["sensor_evidence"]
    rows = [] if evidence is None else evidence["model_observations"]
    spans = []
    for row in rows:
        start, size = row["stdout_offset"], row["stdout_bytes"]
        raw = stdout[start : start + size]
        spans.append(
            dict(
                phase=row["phase"],
                byte_start=start,
                byte_end=start + size,
                raw_base64=base64.b64encode(raw).decode("ascii"),
                sha256=digest(raw),
            )
        )
    validate_sensor_spans(
        {
            **summary,
            "sensor_observation_spans": spans,
            "evidence_inputs": {"backend.stdout.bin": {"size_bytes": len(stdout)}},
        }
    )
    return spans


def import_report(raw: bytes, path: Path, source: dict, events: list[dict]) -> int:
    require(
        len(raw) <= MAX_RECORD_BYTES, "simulation report exceeds record limit", "LIMIT_EXCEEDED"
    )
    report = parse_json(raw)
    sensor = report.get("schema_version") == "embedded-sim-runner.sensor-report.v1"
    wasm = report.get("schema_version") == "embedded-sim-runner.esp-wasm-report.v1"
    fault = report.get("schema_version") == "embedded-sim-runner.gpio-fault-report.v1"
    gpio = fault or report.get("schema_version") == "embedded-sim-runner.gpio-timer-report.v1"
    s3 = report.get("schema_version") == "embedded-sim-runner.qemu-s3-flash-report.v1"
    flash = s3 or report.get("schema_version") == "embedded-sim-runner.qemu-flash-report.v1"
    qemu = report.get("schema_version") == "embedded-sim-runner.qemu-report.v1"
    require(
        wasm
        or sensor
        or gpio
        or flash
        or qemu
        or report.get("schema_version") == "embedded-sim-runner.report.v1",
        "unsupported simulation report",
    )
    for key, value in BOUNDARIES.items():
        require(
            type(report.get(key)) is type(value) and report[key] == value,
            "invalid simulation boundary",
        )
    profile = (
        SENSOR_PROFILE
        if sensor
        else WASM_PROFILE
        if wasm
        else FAULT_PROFILE
        if fault
        else GPIO_PROFILE
        if gpio
        else S3_PROFILE
        if s3
        else FLASH_PROFILE
        if flash
        else "esp32c3-ram-uart-v1"
        if qemu
        else "nrf52840-uart-v1"
    )
    require(report.get("profile") == profile, "unsupported simulation profile")
    require(
        report.get("status") in OUTCOMES
        and report.get("ok") is (report["status"] != "failed")
        and (flash or wasm or report["status"] != "passed_with_model_limits"),
        "simulation verdict mismatch",
    )
    required = (
        {"plan.json", "runtime-lock.json", "model.json", "runner.mjs", "flash-input.bin"}
        | WASM_COMPONENTS
        if wasm
        else {
            "plan.json",
            "runtime-lock.json",
            "model.json",
            "flash-input.bin",
            "flash-work.bin",
            "esp32s3_rev0_rom.bin" if s3 else "esp32c3-rom.bin",
            "efuse-initial.bin",
            "efuse-work.bin",
        }
        if flash
        else {"plan.json", "runtime-lock.json", "firmware.elf", "model.json"}
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
    budget = MAX_FLASH_SOURCE_BYTES if flash or wasm else MAX_SOURCE_BYTES
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
            total + len(raw) <= budget,
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
        digest(
            loaded[
                "flash-input.bin" if flash or wasm else "firmware.elf" if qemu else "firmware.bin"
            ]
        )
        == plan["firmware"]["sha256"],
        "firmware binding differs",
    )
    require(
        digest(loaded["model.json" if flash or wasm or qemu else "model.repl"])
        == plan["model_sha256"],
        "model binding differs",
    )
    require(
        plan.get("profile") == profile
        and plan.get("schema_version")
        == (
            "embedded-sim-runner.sensor-plan.v1"
            if sensor
            else "embedded-sim-runner.esp-wasm-plan.v1"
            if wasm
            else "embedded-sim-runner.gpio-fault-plan.v1"
            if fault
            else "embedded-sim-runner.gpio-timer-plan.v1"
            if gpio
            else "embedded-sim-runner.qemu-s3-flash-plan.v1"
            if s3
            else "embedded-sim-runner.qemu-flash-plan.v1"
            if flash
            else "embedded-sim-runner.qemu-plan.v1"
            if qemu
            else "embedded-sim-runner.plan.v1"
        ),
        "simulation plan profile differs",
    )
    for key, value in BOUNDARIES.items():
        require(
            type(plan.get(key)) is type(value) and plan[key] == value,
            "invalid plan simulation boundary",
        )
    if wasm:
        wasm_binding(report, plan, loaded, source)
    if sensor:
        summary = sensor_summary(report)
        require(
            all(type(plan.get(k)) is type(v) and plan[k] == v for k, v in SENSOR_LABELS.items())
            and plan.get("fault_scenario") == summary["fault_scenario"]
            and plan.get("scenario", {}).get("fault") == summary["fault_request"]
            and plan.get("backend") == "renode"
            and type(plan.get("virtual_ms")) is int
            and plan["virtual_ms"] == 82
            and digest(loaded["run.resc"]) == plan.get("script_sha256"),
            "sensor plan request/context/script differs",
        )
        source.update(summary)
        source["sensor_observation_spans"] = sensor_spans(
            summary, loaded.get("backend.stdout.bin", b"")
        )
        source["warnings"]["model_coverage_incomplete"] = 1
    if gpio:
        summary = gpio_summary(report)
        require(
            all(
                type(plan.get(k)) is type(v) and plan[k] == v
                for k, v in summary.items()
                if k
                in (
                    "model_coverage_complete",
                    "physical_timing_verified",
                    *GPIO_LABELS,
                    "fault_scenario",
                    "fault_scope",
                )
            ),
            "GPIO plan coverage/semantics differ",
        )
        require(
            digest(loaded["run.resc"]) == plan.get("script_sha256"), "GPIO script binding differs"
        )
        source.update(summary)
        if fault:
            require(
                plan.get("scenario", {}).get("fault") == summary["fault_request"],
                "fault request differs from saved plan",
            )
        source["gpio_observation_spans"] = gpio_spans(
            summary, loaded.get("backend.stdout.bin", b"")
        )
        source["warnings"]["model_coverage_incomplete"] = 1
    if flash:
        require(
            digest(loaded["esp32s3_rev0_rom.bin" if s3 else "esp32c3-rom.bin"])
            == plan.get("rom_sha256")
            and digest(loaded["efuse-initial.bin"]) == plan.get("efuse_initial_sha256")
            and all(
                len(loaded[name]) == 4 * 1024 * 1024
                for name in ("flash-input.bin", "flash-work.bin")
            )
            and all(len(loaded[name]) == 1024 for name in ("efuse-initial.bin", "efuse-work.bin")),
            "Flash/ROM/eFuse binding or size differs",
        )
        limits = model_limits(report)
        stderr_lines = (
            loaded.get("backend.stderr.bin", b"").decode("utf-8", errors="replace").splitlines()
        )
        require(
            all(
                stderr_lines.count(row["message"]) == row["count"]
                for row in limits["model_diagnostics"]
            ),
            "saved diagnostic count differs",
        )
        source.update(limits)
    if s3:
        summary = s3_summary(report)
        runtime = parse_json(loaded["runtime-lock.json"])
        model = parse_json(loaded["model.json"])
        require(
            isinstance(runtime, dict)
            and isinstance(model, dict)
            and isinstance(runtime.get("files"), dict),
            "invalid S3 runtime/model document",
        )
        require(
            plan.get("backend") == runtime.get("backend") == summary["backend"]
            and plan.get("backend_version") == runtime.get("version") == summary["backend_version"]
            and runtime.get("archive_sha256") == summary["runtime_archive_sha256"]
            and runtime.get("executable") == "bin/qemu-system-xtensa.exe"
            and runtime.get("files", {}).get("share/qemu/esp32s3_rev0_rom.bin")
            == plan["rom_sha256"]
            and model.get("profile") == profile
            and model.get("backend") == summary["backend"],
            "S3 runtime/ROM/model identity binding differs",
        )
        source.update(summary)
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
        capture_outcome=OUTCOMES[report["status"]],
        time_semantics="simulation_run_host_window_not_uart_event_time",
        host_window=window,
        evidence_inputs=refs,
        extra_input_bytes=total,
        recorded_status=report["status"],
        native_assertions_reexecuted=False,
        virtual_time=copy.deepcopy(report.get("virtual_time")),
        profile=profile,
        saved_records=[
            {"index": 1, "artifact": "selected_report", "byte_start": 0, "byte_end": len(raw)}
        ],
    )
    source["integrity"].update(
        saved_artifacts_hash_verified=True, finish_payload_hash_verified=None
    )
    if gpio:
        validate_gpio_spans(source)
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
