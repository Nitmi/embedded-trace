"""Bounded PPI saved declarations and byte spans, never native firmware policy."""

import base64
import copy
import re

from .adapters import decode_base64
from .common import MAX_SOURCE_BYTES, digest, integer, require, text

PPI_PROFILE = "nrf52840-ppi-v1"
PPI_FAULTS = ("none", "ppi-channel-disable", "ppi-fork-misroute")
PPI_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "event_time_alignment_verified": False,
    "ppi_routing_verified": False,
    "ppi_semantics": "Renode_1.17_TIMER0_COMPARE0_CH0_TEP_FORK_GPIOTE_OUT_subset",
    "fault_semantics": "fixed_monitor_CHENCLR_or_FORK_TEP_not_physical_fault",
    "observation_semantics": "paused_registers_and_guest_GPIO_poll_not_event_time_alignment",
}
PPI_FIELDS = (
    *PPI_LABELS,
    "fault_scenario",
    "fault_request",
    "ppi_evidence",
    "ppi_observation_spans",
    "ppi_sample_spans",
    "ppi_fault_span",
    "native_errors",
)
SAMPLE_KEYS = ("sequence", "a", "b", "sentinel")
REGISTER_KEYS = (
    "timer_event",
    "timer_prescaler",
    "timer_compare",
    "channel_mask",
    "event_endpoint",
    "task_endpoint",
    "fork_endpoint",
    "config0",
    "config1",
    "config2",
    "gpio0_out",
    "gpio1_out",
    "gpio0_in",
    "gpio1_in",
)


def ppi_summary(report):
    require(
        report.get("schema_version") == "embedded-sim-runner.ppi-report.v1"
        and report.get("profile") == PPI_PROFILE
        and all(type(report.get(k)) is type(v) and report[k] == v for k, v in PPI_LABELS.items()),
        "invalid PPI identity/qualification",
    )
    fault, clock, evidence = (
        report.get(k) for k in ("fault_scenario", "virtual_time", "assertions")
    )
    require(type(fault) is str and fault in PPI_FAULTS, "invalid PPI fault")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 40
        and type(clock["completed"]) is bool,
        "invalid PPI clock",
    )
    require(evidence is None or isinstance(evidence, dict), "invalid PPI evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing PPI lacks evidence")
    if evidence is not None:
        require(
            set(evidence)
            == {
                "nominal_regression_passed",
                "nominal_failure",
                "fault",
                "samples",
                "model_observations",
                "fault_scenario",
                *PPI_LABELS,
            }
            and type(evidence.get("nominal_regression_passed")) is bool
            and evidence["fault_scenario"] == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v for k, v in PPI_LABELS.items()
            ),
            "invalid PPI assertion context",
        )
        failure = evidence["nominal_failure"]
        require(failure is None or isinstance(failure, str), "invalid PPI failure")
        if failure is not None:
            text(failure, "PPI failure", 2048)
        effect = evidence["fault"]
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "observed", "not_observed"),
            "invalid PPI effect",
        )
        samples, observations = evidence["samples"], evidence["model_observations"]
        require(isinstance(samples, list) and len(samples) <= 16, "invalid PPI samples")
        for row in samples:
            require(isinstance(row, dict) and set(row) == set(SAMPLE_KEYS), "invalid PPI sample")
            for key in SAMPLE_KEYS:
                integer(row[key], key, 0, 2**32 - 1)
        require(
            isinstance(observations, list) and len(observations) in (0, 16),
            "invalid PPI observations",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {"index", "phase", "registers", "stdout_offset", "stdout_bytes", "stdout_sha256"}
                and type(row["index"]) is int
                and row["index"] == index // 2
                and row["phase"] == ("PRE" if index % 2 == 0 else "POST"),
                "invalid PPI observation fields",
            )
            registers = row["registers"]
            require(
                isinstance(registers, dict) and set(registers) == set(REGISTER_KEYS),
                "invalid PPI register inventory",
            )
            for key in REGISTER_KEYS:
                integer(registers[key], key, 0, 1 if key == "timer_event" else 2**32 - 1)
            integer(row["stdout_offset"], "PPI offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "PPI bytes", 1, 4096)
            require(
                isinstance(row["stdout_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["stdout_sha256"]) is not None,
                "invalid PPI record hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid PPI errors")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"code", "message"}, "invalid PPI error")
        text(error["code"], "PPI error code", 128)
        text(error["message"], "PPI error message", 2048)
    return {
        **PPI_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "stimulus_index": None if fault == "none" else 4},
        "ppi_evidence": copy.deepcopy(evidence),
        "native_errors": copy.deepcopy(errors),
    }


def span(data, start, size):
    raw = data[start : start + size]
    return dict(
        byte_start=start,
        byte_end=start + size,
        raw_base64=base64.b64encode(raw).decode("ascii"),
        sha256=digest(raw),
    )


def ppi_spans(summary, stdout, uart, prefix):
    evidence = summary["ppi_evidence"]
    observations, samples, fault_span = [], [], None
    if evidence is not None:
        observations = [
            span(stdout, r["stdout_offset"], r["stdout_bytes"])
            for r in evidence["model_observations"]
        ]
        cursor = 0
        for index, row in enumerate(evidence["samples"]):
            pattern = (
                re.escape(prefix.encode())
                + (
                    f" {row['sequence']:08X} A={row['a']:08X} B={row['b']:08X}"
                    f" S={row['sentinel']:08X}"
                ).encode()
                + rb"\r?\n"
            )
            match = re.search(rb"(?m)^" + pattern, uart[cursor:])
            require(match is not None, "PPI recorded sample absent from raw UART")
            samples.append(dict(sample=index, **span(uart, cursor + match.start(), len(match[0]))))
            cursor += match.end()
        markers = list(re.finditer(rb"(?m)^SIM_PPI_FAULT\r?\n", stdout))
        if observations:
            require(
                len(markers) == (summary["fault_scenario"] != "none"),
                "PPI fault marker inventory differs",
            )
            if markers:
                fault_span = span(stdout, markers[0].start(), len(markers[0][0]))
    return dict(
        ppi_observation_spans=observations, ppi_sample_spans=samples, ppi_fault_span=fault_span
    )


def validate_ppi_spans(source, uart=None):
    evidence = source["ppi_evidence"]
    obs = [] if evidence is None else evidence["model_observations"]
    rows = [] if evidence is None else evidence["samples"]

    def raw_span(value, filename, cursor=0, row=None, sample=None):
        require(
            isinstance(value, dict)
            and set(value)
            == {
                "byte_start",
                "byte_end",
                "raw_base64",
                "sha256",
                *(() if sample is None else ("sample",)),
            },
            "invalid PPI span fields",
        )
        if sample is not None:
            require(
                type(value["sample"]) is int and value["sample"] == sample,
                "invalid PPI sample index",
            )
        ref = source["evidence_inputs"].get(filename)
        require(isinstance(ref, dict), "missing PPI raw reference")
        start = integer(value["byte_start"], "PPI span start", cursor, ref["size_bytes"])
        end = integer(value["byte_end"], "PPI span end", start + 1, ref["size_bytes"])
        raw = decode_base64(value["raw_base64"])
        require(
            len(raw) == end - start <= (256 if sample is not None else 4096)
            and digest(raw) == value["sha256"],
            "invalid PPI span hash/size",
        )
        if row is not None:
            require(
                start == row["stdout_offset"]
                and len(raw) == row["stdout_bytes"]
                and digest(raw) == row["stdout_sha256"],
                "PPI raw binding differs",
            )
        return raw, end

    for field, items in (("ppi_observation_spans", obs), ("ppi_sample_spans", rows)):
        require(
            isinstance(source.get(field), list) and len(source[field]) == len(items),
            "PPI span inventory differs",
        )
    cursor = 0
    for value, row in zip(source["ppi_observation_spans"], obs, strict=True):
        raw, cursor = raw_span(value, "backend.stdout.bin", cursor, row)
        # Representation only: preserve native register values and verdicts.
        lifecycle = (
            rb"\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{4}\] \[INFO\] "
            rb"nrf52840-ppi: Machine (?:paused|resumed)\.\r?\n"
        )
        field = rb"(?:" + lifecycle + rb"){0,4}([0-9]{1,10})\r?\n"
        match = re.fullmatch(
            rb"SIM_PPI_OBS_"
            + str(row["index"]).encode()
            + b"_"
            + row["phase"].encode()
            + rb"\r?\n"
            + field * 14,
            raw,
        )
        require(
            match is not None
            and list(map(int, match.groups())) == [row["registers"][key] for key in REGISTER_KEYS],
            "PPI model bytes differ from recorded fields",
        )
    require("ppi_fault_span" in source, "missing PPI fault span field")
    fault_span = source["ppi_fault_span"]
    if obs and source["fault_scenario"] != "none":
        raw, end = raw_span(
            fault_span, "backend.stdout.bin", source["ppi_observation_spans"][7]["byte_end"]
        )
        require(
            re.fullmatch(rb"SIM_PPI_FAULT\r?\n", raw) is not None
            and end <= source["ppi_observation_spans"][8]["byte_start"],
            "invalid PPI fault marker/order",
        )
    else:
        require(fault_span is None, "unexpected PPI fault span")
    cursor = 0
    for index, (value, row) in enumerate(zip(source["ppi_sample_spans"], rows, strict=True)):
        raw, cursor = raw_span(value, "uart.bin", cursor, sample=index)
        match = re.fullmatch(
            rb"[ -~]{1,160} ([0-9A-F]{8}) A=([0-9A-F]{8}) B=([0-9A-F]{8})"
            rb" S=([0-9A-F]{8})\r?\n",
            raw,
        )
        require(
            match is not None
            and [int(v, 16) for v in match.groups()] == [row[k] for k in SAMPLE_KEYS],
            "PPI guest bytes differ from recorded fields",
        )
        if uart is not None:
            require(uart[value["byte_start"] : cursor] == raw, "PPI sample span differs from UART")
