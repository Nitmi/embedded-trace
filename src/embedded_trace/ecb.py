"""Bounded ECB saved declarations and byte spans, never native firmware policy."""

import base64
import copy
import re

from .adapters import decode_base64
from .common import MAX_SOURCE_BYTES, digest, integer, require, text

ECB_PROFILE = "nrf52840-ecb-v1"
ECB_FAULTS = ("none", "plaintext-stuck", "context-redirect")
ECB_LABELS = {
    "model_coverage_complete": False,
    "physical_timing_verified": False,
    "event_time_alignment_verified": False,
    "crypto_hardware_verified": False,
    "cryptographic_security_qualified": False,
    "side_channel_resistance_verified": False,
    "ecb_semantics": "Renode_1.17_fixed_AES128_block_NIST_F1_1_not_security_certification",
    "fault_semantics": "fixed_monitor_plaintext_repeat_or_valid_alternate_context_pointer",
    "observation_semantics": "paused_model_SRAM_guest_handshake_not_encryption_latency",
}

ECB_FIELDS = (
    *ECB_LABELS,
    "fault_scenario",
    "fault_request",
    "ecb_evidence",
    "ecb_observation_spans",
    "ecb_sample_spans",
    "ecb_fault_span",
    "native_errors",
)
SAMPLE_KEYS = ("sequence", "ciphertext", "end", "guard_low", "guard_high")
REGISTER_KEYS = ("data_pointer", "end", "interrupt_mask", "mailbox") + tuple(
    prefix + name
    for prefix in ("", "alternate_")
    for name in (
        "guard_low",
        *("key" + str(i) for i in range(4)),
        *("plaintext" + str(i) for i in range(4)),
        *("ciphertext" + str(i) for i in range(4)),
        "guard_high",
    )
)


def ecb_summary(report):
    require(
        report.get("schema_version") == "embedded-sim-runner.ecb-report.v1"
        and report.get("profile") == ECB_PROFILE
        and all(type(report.get(k)) is type(v) and report[k] == v for k, v in ECB_LABELS.items()),
        "invalid ECB identity/qualification",
    )
    fault, clock, evidence = (
        report.get(k) for k in ("fault_scenario", "virtual_time", "assertions")
    )
    require(type(fault) is str and fault in ECB_FAULTS, "invalid ECB fault")
    require(
        isinstance(clock, dict)
        and set(clock) == {"domain", "requested_ms", "completed"}
        and clock["domain"] == "renode_emulation"
        and type(clock["requested_ms"]) is int
        and clock["requested_ms"] == 40
        and type(clock["completed"]) is bool,
        "invalid ECB clock",
    )
    require(evidence is None or isinstance(evidence, dict), "invalid ECB evidence")
    require(not report["ok"] or isinstance(evidence, dict), "passing ECB lacks evidence")
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
                *ECB_LABELS,
            }
            and type(evidence.get("nominal_regression_passed")) is bool
            and evidence["fault_scenario"] == fault
            and all(
                type(evidence.get(k)) is type(v) and evidence[k] == v for k, v in ECB_LABELS.items()
            ),
            "invalid ECB assertion context",
        )
        failure = evidence["nominal_failure"]
        require(failure is None or isinstance(failure, str), "invalid ECB failure")
        if failure is not None:
            text(failure, "ECB failure", 2048)
        effect = evidence["fault"]
        require(
            isinstance(effect, dict)
            and set(effect) == {"id", "effect_observed", "status"}
            and effect["id"] == fault
            and (effect["effect_observed"] is None or type(effect["effect_observed"]) is bool)
            and effect["status"] in ("not_evaluated", "observed", "not_observed"),
            "invalid ECB effect",
        )
        samples, observations = evidence["samples"], evidence["model_observations"]
        require(isinstance(samples, list) and len(samples) <= 16, "invalid ECB samples")
        for row in samples:
            require(isinstance(row, dict) and set(row) == set(SAMPLE_KEYS), "invalid ECB sample")
            require(
                isinstance(row["ciphertext"], str)
                and re.fullmatch(r"[0-9a-f]{32}", row["ciphertext"]) is not None,
                "invalid ECB ciphertext representation",
            )
            for key in SAMPLE_KEYS:
                if key != "ciphertext":
                    integer(row[key], key, 0, 2**32 - 1)
        require(
            isinstance(observations, list) and len(observations) in (0, 16),
            "invalid ECB observations",
        )
        for index, row in enumerate(observations):
            require(
                isinstance(row, dict)
                and set(row)
                == {"index", "phase", "registers", "stdout_offset", "stdout_bytes", "stdout_sha256"}
                and type(row["index"]) is int
                and row["index"] == index // 2
                and row["phase"] == ("PRE" if index % 2 == 0 else "POST"),
                "invalid ECB observation fields",
            )
            registers = row["registers"]
            require(
                isinstance(registers, dict) and set(registers) == set(REGISTER_KEYS),
                "invalid ECB register inventory",
            )
            for key in REGISTER_KEYS:
                integer(
                    registers[key],
                    key,
                    0,
                    2**32 - 1,
                )
            integer(row["stdout_offset"], "ECB offset", 0, MAX_SOURCE_BYTES)
            integer(row["stdout_bytes"], "ECB bytes", 1, 16384)
            require(
                isinstance(row["stdout_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["stdout_sha256"]) is not None,
                "invalid ECB record hash",
            )
    errors = report.get("errors")
    require(isinstance(errors, list) and len(errors) <= 16, "invalid ECB errors")
    for error in errors:
        require(isinstance(error, dict) and set(error) == {"code", "message"}, "invalid ECB error")
        text(error["code"], "ECB error code", 128)
        text(error["message"], "ECB error message", 2048)
    return {
        **ECB_LABELS,
        "fault_scenario": fault,
        "fault_request": {"id": fault, "stimulus_index": None if fault == "none" else 4},
        "ecb_evidence": copy.deepcopy(evidence),
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


def ecb_spans(summary, stdout, uart, prefix):
    evidence = summary["ecb_evidence"]
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
                    f" {row['sequence']:08X} OUT={row['ciphertext'].upper()} END={row['end']:08X}"
                    f" LO={row['guard_low']:08X} HI={row['guard_high']:08X}"
                ).encode()
                + rb"\r?\n"
            )
            match = re.search(rb"(?m)^" + pattern, uart[cursor:])
            require(match is not None, "ECB recorded sample absent from raw UART")
            samples.append(dict(sample=index, **span(uart, cursor + match.start(), len(match[0]))))
            cursor += match.end()
        markers = list(re.finditer(rb"(?m)^SIM_ECB_FAULT\r?\n", stdout))
        if observations:
            require(
                len(markers) == (summary["fault_scenario"] != "none"),
                "ECB fault marker inventory differs",
            )
            if markers:
                fault_span = span(stdout, markers[0].start(), len(markers[0][0]))
    return dict(
        ecb_observation_spans=observations,
        ecb_sample_spans=samples,
        ecb_fault_span=fault_span,
    )


def validate_ecb_spans(source, uart=None):
    evidence = source["ecb_evidence"]
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
            "invalid ECB span fields",
        )
        if sample is not None:
            require(
                type(value["sample"]) is int and value["sample"] == sample,
                "invalid ECB sample index",
            )
        ref = source["evidence_inputs"].get(filename)
        require(isinstance(ref, dict), "missing ECB raw reference")
        start = integer(value["byte_start"], "ECB span start", cursor, ref["size_bytes"])
        end = integer(value["byte_end"], "ECB span end", start + 1, ref["size_bytes"])
        raw = decode_base64(value["raw_base64"])
        require(
            len(raw) == end - start <= (256 if sample is not None else 16384)
            and digest(raw) == value["sha256"],
            "invalid ECB span hash/size",
        )
        if row is not None:
            require(
                start == row["stdout_offset"]
                and len(raw) == row["stdout_bytes"]
                and digest(raw) == row["stdout_sha256"],
                "ECB raw binding differs",
            )
        return raw, end

    for field, items in (("ecb_observation_spans", obs), ("ecb_sample_spans", rows)):
        require(
            isinstance(source.get(field), list) and len(source[field]) == len(items),
            "ECB span inventory differs",
        )
    cursor = 0
    for value, row in zip(source["ecb_observation_spans"], obs, strict=True):
        raw, cursor = raw_span(value, "backend.stdout.bin", cursor, row)
        # Representation only: preserve native register values and verdicts.
        lifecycle = (
            rb"\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{4}\] \[INFO\] "
            rb"nrf52840-ecb: Machine (?:paused|resumed)\.\r?\n"
        )
        field = rb"(?:" + lifecycle + rb"){0,4}([0-9]{1,10})\r?\n"
        match = re.fullmatch(
            rb"SIM_ECB_OBS_"
            + str(row["index"]).encode()
            + b"_"
            + row["phase"].encode()
            + rb"\r?\n"
            + field * 32,
            raw,
        )
        require(
            match is not None
            and list(map(int, match.groups())) == [row["registers"][key] for key in REGISTER_KEYS],
            "ECB model bytes differ from recorded fields",
        )
    require("ecb_fault_span" in source, "missing ECB fault span field")
    fault_span = source["ecb_fault_span"]
    if obs and source["fault_scenario"] != "none":
        raw, end = raw_span(
            fault_span, "backend.stdout.bin", source["ecb_observation_spans"][7]["byte_end"]
        )
        require(
            re.fullmatch(rb"SIM_ECB_FAULT\r?\n", raw) is not None
            and end <= source["ecb_observation_spans"][8]["byte_start"],
            "invalid ECB fault marker/order",
        )
    else:
        require(fault_span is None, "unexpected ECB fault span")
    cursor = 0
    for index, (value, row) in enumerate(zip(source["ecb_sample_spans"], rows, strict=True)):
        raw, cursor = raw_span(value, "uart.bin", cursor, sample=index)
        match = re.fullmatch(
            rb"[ -~]{1,160} ([0-9A-F]{8}) OUT=([0-9A-F]{32}) END=([0-9A-F]{8})"
            rb" LO=([0-9A-F]{8}) HI=([0-9A-F]{8})\r?\n",
            raw,
        )
        require(
            match is not None
            and [int(v, 16) if i != 1 else v.decode().lower() for i, v in enumerate(match.groups())]
            == [row[k] for k in SAMPLE_KEYS],
            "ECB guest bytes differ from recorded fields",
        )
        if uart is not None:
            require(uart[value["byte_start"] : cursor] == raw, "ECB sample span differs from UART")
