"""Bounded UARTE saved declarations and byte spans, never native firmware policy."""

import base64
import copy
import re

from .adapters import decode_base64
from .common import MAX_SOURCE_BYTES, digest, integer, require, text

UARTE_PROFILE = "nrf52840-uarte-dma-v1"
UARTE_FAULTS = ("none", "rx-short-buffer", "rx-pointer-shift")
UARTE_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "event_time_alignment_verified": False,
    "dma_hardware_verified": False,
    "uart_electrical_behavior_verified": False,
    "uarte_semantics": "Renode_1.17_UARTE1_RX_PTR_MAXCNT_AMOUNT_events_and_guarded_SRAM",
    "fault_semantics": "fixed_monitor_short_MAXCNT_or_shifted_PTR_with_STARTRX_not_wire_fault",
    "observation_semantics": "paused_model_and_SRAM_before_guest_service_not_DMA_latency",
}

UARTE_FIELDS = (
    *UARTE_LABELS,
    "fault_scenario",
    "fault_request",
    "uarte_evidence",
    "uarte_observation_spans",
    "uarte_sample_spans",
    "uarte_fault_span",
    "native_errors",
)
SAMPLE_KEYS = ("sequence", "word", "amount", "guard_low", "guard_high")
REGISTER_KEYS = (
    "enable",
    "rx_pointer",
    "rx_max_count",
    "rx_amount",
    "end_rx",
    "rx_ready",
    "rx_started",
    "rx_timeout",
    "interrupt_mask",
    "guard_low",
    "buffer_word",
    "guard_high",
)


def uarte_summary(report):
    require(
        report.get("schema_version") == "embedded-sim-runner.uarte-dma-report.v1"
        and report.get("profile") == UARTE_PROFILE
        and all(type(report.get(k)) is type(v) and report[k] == v for k, v in UARTE_LABELS.items()),
        "invalid UARTE identity/qualification",
    )
    fault, clock, evidence = (
        report.get(k) for k in ("fault_scenario", "virtual_time", "assertions")
    )
    require(type(fault) is str and fault in UARTE_FAULTS, "invalid UARTE fault")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 40
        and type(clock["completed"]) is bool,
        "invalid UARTE clock",
    )
    require(evidence is None or isinstance(evidence, dict), "invalid UARTE evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing UARTE lacks evidence")
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
                *UARTE_LABELS,
            }
            and type(evidence.get("nominal_regression_passed")) is bool
            and evidence["fault_scenario"] == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v
                for k, v in UARTE_LABELS.items()
            ),
            "invalid UARTE assertion context",
        )
        failure = evidence["nominal_failure"]
        require(failure is None or isinstance(failure, str), "invalid UARTE failure")
        if failure is not None:
            text(failure, "UARTE failure", 2048)
        effect = evidence["fault"]
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "observed", "not_observed"),
            "invalid UARTE effect",
        )
        samples, observations = evidence["samples"], evidence["model_observations"]
        require(isinstance(samples, list) and len(samples) <= 16, "invalid UARTE samples")
        for row in samples:
            require(isinstance(row, dict) and set(row) == set(SAMPLE_KEYS), "invalid UARTE sample")
            for key in SAMPLE_KEYS:
                integer(row[key], key, 0, 2**32 - 1)
        require(
            isinstance(observations, list) and len(observations) in (0, 16),
            "invalid UARTE observations",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {"index", "phase", "registers", "stdout_offset", "stdout_bytes", "stdout_sha256"}
                and type(row["index"]) is int
                and row["index"] == index // 2
                and row["phase"] == ("PRE" if index % 2 == 0 else "POST"),
                "invalid UARTE observation fields",
            )
            registers = row["registers"]
            require(
                isinstance(registers, dict) and set(registers) == set(REGISTER_KEYS),
                "invalid UARTE register inventory",
            )
            for key in REGISTER_KEYS:
                integer(
                    registers[key],
                    key,
                    0,
                    1 if key in ("end_rx", "rx_ready", "rx_started", "rx_timeout") else 2**32 - 1,
                )
            integer(row["stdout_offset"], "UARTE offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "UARTE bytes", 1, 4096)
            require(
                isinstance(row["stdout_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["stdout_sha256"]) is not None,
                "invalid UARTE record hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid UARTE errors")
    for error in errors:
        require(
            isinstance(error, dict) and set(error) == {"code", "message"}, "invalid UARTE error"
        )
        text(error["code"], "UARTE error code", 128)
        text(error["message"], "UARTE error message", 2048)
    return {
        **UARTE_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "stimulus_index": None if fault == "none" else 4},
        "uarte_evidence": copy.deepcopy(evidence),
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


def uarte_spans(summary, stdout, uart, prefix):
    evidence = summary["uarte_evidence"]
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
                    f" {row['sequence']:08X} WORD={row['word']:08X} N={row['amount']:08X}"
                    f" LO={row['guard_low']:08X} HI={row['guard_high']:08X}"
                ).encode()
                + rb"\r?\n"
            )
            match = re.search(rb"(?m)^" + pattern, uart[cursor:])
            require(match is not None, "UARTE recorded sample absent from raw UART")
            samples.append(dict(sample=index, **span(uart, cursor + match.start(), len(match[0]))))
            cursor += match.end()
        markers = list(re.finditer(rb"(?m)^SIM_UARTE_FAULT\r?\n", stdout))
        if observations:
            require(
                len(markers) == (summary["fault_scenario"] != "none"),
                "UARTE fault marker inventory differs",
            )
            if markers:
                fault_span = span(stdout, markers[0].start(), len(markers[0][0]))
    return dict(
        uarte_observation_spans=observations,
        uarte_sample_spans=samples,
        uarte_fault_span=fault_span,
    )


def validate_uarte_spans(source, uart=None):
    evidence = source["uarte_evidence"]
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
            "invalid UARTE span fields",
        )
        if sample is not None:
            require(
                type(value["sample"]) is int and value["sample"] == sample,
                "invalid UARTE sample index",
            )
        ref = source["evidence_inputs"].get(filename)
        require(isinstance(ref, dict), "missing UARTE raw reference")
        start = integer(value["byte_start"], "UARTE span start", cursor, ref["size_bytes"])
        end = integer(value["byte_end"], "UARTE span end", start + 1, ref["size_bytes"])
        raw = decode_base64(value["raw_base64"])
        require(
            len(raw) == end - start <= (256 if sample is not None else 4096)
            and digest(raw) == value["sha256"],
            "invalid UARTE span hash/size",
        )
        if row is not None:
            require(
                start == row["stdout_offset"]
                and len(raw) == row["stdout_bytes"]
                and digest(raw) == row["stdout_sha256"],
                "UARTE raw binding differs",
            )
        return raw, end

    for field, items in (("uarte_observation_spans", obs), ("uarte_sample_spans", rows)):
        require(
            isinstance(source.get(field), list) and len(source[field]) == len(items),
            "UARTE span inventory differs",
        )
    cursor = 0
    for value, row in zip(source["uarte_observation_spans"], obs, strict=True):
        raw, cursor = raw_span(value, "backend.stdout.bin", cursor, row)
        # Representation only: preserve native register values and verdicts.
        lifecycle = (
            rb"\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{4}\] \[INFO\] "
            rb"nrf52840-uarte-dma: Machine (?:paused|resumed)\.\r?\n"
        )
        field = rb"(?:" + lifecycle + rb"){0,4}([0-9]{1,10})\r?\n"
        match = re.fullmatch(
            rb"SIM_UARTE_OBS_"
            + str(row["index"]).encode()
            + b"_"
            + row["phase"].encode()
            + rb"\r?\n"
            + field * 12,
            raw,
        )
        require(
            match is not None
            and list(map(int, match.groups())) == [row["registers"][key] for key in REGISTER_KEYS],
            "UARTE model bytes differ from recorded fields",
        )
    require("uarte_fault_span" in source, "missing UARTE fault span field")
    fault_span = source["uarte_fault_span"]
    if obs and source["fault_scenario"] != "none":
        raw, end = raw_span(
            fault_span, "backend.stdout.bin", source["uarte_observation_spans"][7]["byte_end"]
        )
        require(
            re.fullmatch(rb"SIM_UARTE_FAULT\r?\n", raw) is not None
            and end <= source["uarte_observation_spans"][8]["byte_start"],
            "invalid UARTE fault marker/order",
        )
    else:
        require(fault_span is None, "unexpected UARTE fault span")
    cursor = 0
    for index, (value, row) in enumerate(zip(source["uarte_sample_spans"], rows, strict=True)):
        raw, cursor = raw_span(value, "uart.bin", cursor, sample=index)
        match = re.fullmatch(
            rb"[ -~]{1,160} ([0-9A-F]{8}) WORD=([0-9A-F]{8}) N=([0-9A-F]{8})"
            rb" LO=([0-9A-F]{8}) HI=([0-9A-F]{8})\r?\n",
            raw,
        )
        require(
            match is not None
            and [int(v, 16) for v in match.groups()] == [row[k] for k in SAMPLE_KEYS],
            "UARTE guest bytes differ from recorded fields",
        )
        if uart is not None:
            require(
                uart[value["byte_start"] : cursor] == raw, "UARTE sample span differs from UART"
            )
