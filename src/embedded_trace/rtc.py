"""Bounded saved RTC declarations and raw representations, never firmware policy."""

import base64
import copy
import re

from .adapters import decode_base64
from .common import MAX_SOURCE_BYTES, digest, integer, require, text

RTC_PROFILE = "nrf52840-rtc-v1"
RTC_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "low_power_behavior_verified": False,
    "rtc_semantics": "Renode_1.17_32768Hz_divider_and_COMPARE0_IRQ_not_LFCLK_hardware",
    "fault_semantics": "fixed_RTC_TASKS_STOP_or_INTENCLR_not_physical_fault",
    "observation_semantics": "paused_model_registers_and_guest_IRQ_samples_not_host_time",
}
RTC_FIELDS = (
    *RTC_LABELS,
    "fault_scenario",
    "fault_request",
    "rtc_evidence",
    "rtc_observation_spans",
    "rtc_sample_spans",
    "rtc_fault_span",
    "native_errors",
)
SAMPLE_KEYS = (
    "sequence",
    "counter",
    "event_before",
    "event_after",
    "next_compare",
    "prescaler",
    "irq_vector",
)
MODEL_KEYS = ("counter", "prescaler", "compare", "event", "interrupt_mask")


def rtc_summary(report):
    require(
        report.get("schema_version") == "embedded-sim-runner.rtc-report.v1"
        and report.get("profile") == RTC_PROFILE
        and all(type(report.get(k)) is type(v) and report[k] == v for k, v in RTC_LABELS.items()),
        "invalid RTC identity/qualification",
    )
    fault, clock, evidence = (
        report.get(k) for k in ("fault_scenario", "virtual_time", "assertions")
    )
    require(
        type(fault) is str and fault in ("none", "rtc-stop", "rtc-irq-mask"), "invalid RTC fault"
    )
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 162
        and type(clock["completed"]) is bool,
        "invalid RTC clock",
    )
    require(evidence is None or isinstance(evidence, dict), "invalid RTC evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing RTC lacks evidence")
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
                *RTC_LABELS,
            }
            and type(evidence.get("nominal_regression_passed")) is bool
            and evidence["fault_scenario"] == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v for k, v in RTC_LABELS.items()
            ),
            "invalid RTC assertion context",
        )
        failure = evidence["nominal_failure"]
        require(failure is None or isinstance(failure, str), "invalid RTC failure")
        if failure is not None:
            text(failure, "RTC failure", 2048)
        effect = evidence["fault"]
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "observed", "not_observed"),
            "invalid RTC effect",
        )
        samples, observations = evidence["samples"], evidence["model_observations"]
        require(isinstance(samples, list) and len(samples) <= 64, "invalid RTC samples")
        for row in samples:
            require(isinstance(row, dict) and set(row) == set(SAMPLE_KEYS), "invalid RTC sample")
            for key in SAMPLE_KEYS:
                integer(row[key], key, 0, 2**32 - 1)
        require(
            isinstance(observations, list) and len(observations) in (0, 4),
            "invalid RTC observations",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {"index", *MODEL_KEYS, "stdout_offset", "stdout_bytes", "stdout_sha256"}
                and type(row["index"]) is int
                and row["index"] == index,
                "invalid RTC observation fields",
            )
            for key in MODEL_KEYS:
                integer(row[key], key, 0, 2**32 - 1)
            integer(row["stdout_offset"], "RTC offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "RTC bytes", 1, 256)
            require(
                isinstance(row["stdout_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["stdout_sha256"]) is not None,
                "invalid RTC record hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid RTC errors")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"code", "message"}, "invalid RTC error")
        text(error["code"], "RTC error code", 128)
        text(error["message"], "RTC error message", 2048)
    return {
        **RTC_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "requested_virtual_ms": None if fault == "none" else 42},
        "rtc_evidence": copy.deepcopy(evidence),
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


def rtc_spans(summary, stdout, uart, prefix):
    evidence = summary["rtc_evidence"]
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
                    f" {row['sequence']:08X} C={row['counter']:08X} E={row['event_before']:08X}"
                    f" A={row['event_after']:08X} N={row['next_compare']:08X}"
                    f" P={row['prescaler']:08X} V={row['irq_vector']:08X}"
                ).encode()
                + rb"\r?\n"
            )
            match = re.search(rb"(?m)^" + pattern, uart[cursor:])
            require(match is not None, "RTC recorded sample absent from raw UART")
            samples.append(dict(sample=index, **span(uart, cursor + match.start(), len(match[0]))))
            cursor += match.end()
        markers = list(re.finditer(rb"(?m)^SIM_RTC_FAULT\r?\n", stdout))
        # Missing model evidence remains unknown; do not demand a completed fault execution.
        if observations:
            require(
                len(markers) == (summary["fault_scenario"] != "none"),
                "RTC fault marker inventory differs",
            )
            if markers:
                fault_span = span(stdout, markers[0].start(), len(markers[0][0]))
    return dict(
        rtc_observation_spans=observations, rtc_sample_spans=samples, rtc_fault_span=fault_span
    )


def validate_rtc_spans(source, uart=None):
    evidence = source["rtc_evidence"]
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
            "invalid RTC span fields",
        )
        if sample is not None:
            require(
                type(value["sample"]) is int and value["sample"] == sample,
                "invalid RTC sample index",
            )
        ref = source["evidence_inputs"].get(filename)
        require(isinstance(ref, dict), "missing RTC raw reference")
        start = integer(value["byte_start"], "RTC span start", cursor, ref["size_bytes"])
        end = integer(value["byte_end"], "RTC span end", start + 1, ref["size_bytes"])
        raw = decode_base64(value["raw_base64"])
        require(
            len(raw) == end - start <= 256 and digest(raw) == value["sha256"],
            "invalid RTC span hash/size",
        )
        if row is not None:
            require(
                start == row["stdout_offset"]
                and len(raw) == row["stdout_bytes"]
                and digest(raw) == row["stdout_sha256"],
                "RTC raw binding differs",
            )
        return raw, end

    for field, items in (("rtc_observation_spans", obs), ("rtc_sample_spans", rows)):
        require(
            isinstance(source.get(field), list) and len(source[field]) == len(items),
            "RTC span inventory differs",
        )
    cursor = 0
    for value, row in zip(source["rtc_observation_spans"], obs, strict=True):
        raw, cursor = raw_span(value, "backend.stdout.bin", cursor, row)
        match = re.fullmatch(
            rb"SIM_RTC_OBS_" + str(row["index"]).encode() + rb"\r?\n" + rb"([0-9]{1,10})\r?\n" * 5,
            raw,
        )
        require(
            match is not None and list(map(int, match.groups())) == [row[k] for k in MODEL_KEYS],
            "RTC model bytes differ from recorded fields",
        )
    require("rtc_fault_span" in source, "missing RTC fault span field")
    fault_span = source["rtc_fault_span"]
    if obs and source["fault_scenario"] != "none":
        raw, end = raw_span(
            fault_span, "backend.stdout.bin", source["rtc_observation_spans"][0]["byte_end"]
        )
        require(
            re.fullmatch(rb"SIM_RTC_FAULT\r?\n", raw) is not None
            and end <= source["rtc_observation_spans"][1]["byte_start"],
            "invalid RTC fault marker/order",
        )
    else:
        require(fault_span is None, "unexpected RTC fault span")
    cursor = 0
    for index, (value, row) in enumerate(zip(source["rtc_sample_spans"], rows, strict=True)):
        raw, cursor = raw_span(value, "uart.bin", cursor, sample=index)
        match = re.fullmatch(
            rb"[ -~]{1,160} ([0-9A-F]{8}) C=([0-9A-F]{8}) E=([0-9A-F]{8})"
            rb" A=([0-9A-F]{8}) N=([0-9A-F]{8}) P=([0-9A-F]{8}) V=([0-9A-F]{8})\r?\n",
            raw,
        )
        require(
            match is not None
            and [int(v, 16) for v in match.groups()] == [row[k] for k in SAMPLE_KEYS],
            "RTC guest bytes differ from recorded fields",
        )
        if uart is not None:
            require(uart[value["byte_start"] : cursor] == raw, "RTC sample span differs from UART")
