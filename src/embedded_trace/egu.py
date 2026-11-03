"""Bounded saved EGU declarations and raw representations, never firmware policy."""

import base64
import copy
import re

from .adapters import decode_base64
from .common import MAX_SOURCE_BYTES, digest, integer, require, text

EGU_PROFILE = "nrf52840-egu-v1"
EGU_FAULTS = ("none", "egu-irq-mask", "egu-channel-misroute")
EGU_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "ppi_routing_verified": False,
    "egu_semantics": "Renode_1.17_TASKS_TRIGGER_EVENTS_TRIGGERED_INTEN_IRQ20",
    "fault_semantics": "fixed_monitor_INTENCLR_or_TASK_channel_substitution_not_physical_fault",
    "observation_semantics": "paused_pre_post_registers_and_guest_ISR_samples_not_host_time",
}
EGU_FIELDS = (
    *EGU_LABELS,
    "fault_scenario",
    "fault_request",
    "egu_evidence",
    "egu_observation_spans",
    "egu_sample_spans",
    "egu_fault_span",
    "native_errors",
)
SAMPLE_KEYS = (
    "sequence",
    "channel",
    "event_before",
    "event_after",
    "interrupt_mask",
    "irq_vector",
)
MODEL_KEYS = ("events", "interrupt_mask")


def egu_summary(report):
    require(
        report.get("schema_version") == "embedded-sim-runner.egu-report.v1"
        and report.get("profile") == EGU_PROFILE
        and all(type(report.get(k)) is type(v) and report[k] == v for k, v in EGU_LABELS.items()),
        "invalid EGU identity/qualification",
    )
    fault, clock, evidence = (
        report.get(k) for k in ("fault_scenario", "virtual_time", "assertions")
    )
    require(
        type(fault) is str and fault in ("none", "egu-channel-misroute", "egu-irq-mask"),
        "invalid EGU fault",
    )
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 40
        and type(clock["completed"]) is bool,
        "invalid EGU clock",
    )
    require(evidence is None or isinstance(evidence, dict), "invalid EGU evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing EGU lacks evidence")
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
                *EGU_LABELS,
            }
            and type(evidence.get("nominal_regression_passed")) is bool
            and evidence["fault_scenario"] == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v for k, v in EGU_LABELS.items()
            ),
            "invalid EGU assertion context",
        )
        failure = evidence["nominal_failure"]
        require(failure is None or isinstance(failure, str), "invalid EGU failure")
        if failure is not None:
            text(failure, "EGU failure", 2048)
        effect = evidence["fault"]
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "observed", "not_observed"),
            "invalid EGU effect",
        )
        samples, observations = evidence["samples"], evidence["model_observations"]
        require(isinstance(samples, list) and len(samples) <= 32, "invalid EGU samples")
        for row in samples:
            require(isinstance(row, dict) and set(row) == set(SAMPLE_KEYS), "invalid EGU sample")
            for key in SAMPLE_KEYS:
                integer(row[key], key, 0, 2**32 - 1)
        require(
            isinstance(observations, list) and len(observations) in (0, 18),
            "invalid EGU observations",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {"index", "phase", *MODEL_KEYS, "stdout_offset", "stdout_bytes", "stdout_sha256"}
                and type(row["index"]) is int
                and row["index"] == index // 2
                and row["phase"] == ("PRE" if index % 2 == 0 else "POST"),
                "invalid EGU observation fields",
            )
            require(
                isinstance(row["events"], list) and len(row["events"]) == 4,
                "invalid EGU event inventory",
            )
            for value in row["events"]:
                integer(value, "EGU event bit", 0, 1)
            integer(row["interrupt_mask"], "EGU interrupt mask", 0, 65535)
            integer(row["stdout_offset"], "EGU offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "EGU bytes", 1, 2048)
            require(
                isinstance(row["stdout_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["stdout_sha256"]) is not None,
                "invalid EGU record hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid EGU errors")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"code", "message"}, "invalid EGU error")
        text(error["code"], "EGU error code", 128)
        text(error["message"], "EGU error message", 2048)
    return {
        **EGU_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "stimulus_index": None if fault == "none" else 4},
        "egu_evidence": copy.deepcopy(evidence),
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


def egu_spans(summary, stdout, uart, prefix):
    evidence = summary["egu_evidence"]
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
                    f" {row['sequence']:08X} C={row['channel']:08X} E={row['event_before']:08X}"
                    f" A={row['event_after']:08X} M={row['interrupt_mask']:08X}"
                    f" V={row['irq_vector']:08X}"
                ).encode()
                + rb"\r?\n"
            )
            match = re.search(rb"(?m)^" + pattern, uart[cursor:])
            require(match is not None, "EGU recorded sample absent from raw UART")
            samples.append(dict(sample=index, **span(uart, cursor + match.start(), len(match[0]))))
            cursor += match.end()
        markers = list(re.finditer(rb"(?m)^SIM_EGU_FAULT\r?\n", stdout))
        # Missing model evidence remains unknown; do not demand a completed fault execution.
        if observations:
            require(
                len(markers) == (summary["fault_scenario"] != "none"),
                "EGU fault marker inventory differs",
            )
            if markers:
                fault_span = span(stdout, markers[0].start(), len(markers[0][0]))
    return dict(
        egu_observation_spans=observations, egu_sample_spans=samples, egu_fault_span=fault_span
    )


def validate_egu_spans(source, uart=None):
    evidence = source["egu_evidence"]
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
            "invalid EGU span fields",
        )
        if sample is not None:
            require(
                type(value["sample"]) is int and value["sample"] == sample,
                "invalid EGU sample index",
            )
        ref = source["evidence_inputs"].get(filename)
        require(isinstance(ref, dict), "missing EGU raw reference")
        start = integer(value["byte_start"], "EGU span start", cursor, ref["size_bytes"])
        end = integer(value["byte_end"], "EGU span end", start + 1, ref["size_bytes"])
        raw = decode_base64(value["raw_base64"])
        require(
            len(raw) == end - start <= (256 if sample is not None else 2048)
            and digest(raw) == value["sha256"],
            "invalid EGU span hash/size",
        )
        if row is not None:
            require(
                start == row["stdout_offset"]
                and len(raw) == row["stdout_bytes"]
                and digest(raw) == row["stdout_sha256"],
                "EGU raw binding differs",
            )
        return raw, end

    for field, items in (("egu_observation_spans", obs), ("egu_sample_spans", rows)):
        require(
            isinstance(source.get(field), list) and len(source[field]) == len(items),
            "EGU span inventory differs",
        )
    cursor = 0
    for value, row in zip(source["egu_observation_spans"], obs, strict=True):
        raw, cursor = raw_span(value, "backend.stdout.bin", cursor, row)
        # Check only the saved byte representation, including native async INFO.
        # Do not infer whether the event/mask/ISR values constitute a passing run.
        lifecycle = (
            rb"\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{4}\] \[INFO\] "
            rb"nrf52840-egu: Machine (?:paused|resumed)\.\r?\n"
        )
        field = rb"(?:" + lifecycle + rb"){0,4}([0-9]{1,10})\r?\n"
        match = re.fullmatch(
            rb"SIM_EGU_OBS_"
            + str(row["index"]).encode()
            + b"_"
            + row["phase"].encode()
            + rb"\r?\n"
            + field * 5,
            raw,
        )
        require(
            match is not None
            and list(map(int, match.groups())) == [*row["events"], row["interrupt_mask"]],
            "EGU model bytes differ from recorded fields",
        )
    require("egu_fault_span" in source, "missing EGU fault span field")
    fault_span = source["egu_fault_span"]
    if obs and source["fault_scenario"] != "none":
        raw, end = raw_span(
            fault_span, "backend.stdout.bin", source["egu_observation_spans"][7]["byte_end"]
        )
        require(
            re.fullmatch(rb"SIM_EGU_FAULT\r?\n", raw) is not None
            and end <= source["egu_observation_spans"][8]["byte_start"],
            "invalid EGU fault marker/order",
        )
    else:
        require(fault_span is None, "unexpected EGU fault span")
    cursor = 0
    for index, (value, row) in enumerate(zip(source["egu_sample_spans"], rows, strict=True)):
        raw, cursor = raw_span(value, "uart.bin", cursor, sample=index)
        match = re.fullmatch(
            rb"[ -~]{1,160} ([0-9A-F]{8}) C=([0-9A-F]{8}) E=([0-9A-F]{8})"
            rb" A=([0-9A-F]{8}) M=([0-9A-F]{8}) V=([0-9A-F]{8})\r?\n",
            raw,
        )
        require(
            match is not None
            and [int(v, 16) for v in match.groups()] == [row[k] for k in SAMPLE_KEYS],
            "EGU guest bytes differ from recorded fields",
        )
        if uart is not None:
            require(uart[value["byte_start"] : cursor] == raw, "EGU sample span differs from UART")
