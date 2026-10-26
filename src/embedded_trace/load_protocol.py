"""Load evidence v1 consistency rules, vendored byte-identically by HIL and Trace.

Standard library only. No file I/O, native imports, XML reconstruction or SCPI
session replay. This validates recorded bindings, comparisons and raw spans.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re

MAX_BUNDLE = 16 * 1024 * 1024
MAX_MANIFEST = 16384
LIMITS = dict(
    report=1048576,
    spec=65536,
    capture=1048576,
    native_result=131072,
    junit=1048576,
    plan=32768,
    transcript=1048576,
)
QUANTITIES = ("voltage_v", "current_a", "power_w")
METRICS = tuple(f"{s}_{q}" for q in QUANTITIES for s in ("minimum", "maximum", "mean"))
TIME = "recorded_host_query_windows_not_simultaneous_instrument_samples"
NATIVE_FLAGS = dict.fromkeys(
    (
        "hardware_access",
        "executables_started",
        "outputs_commanded",
        "authorization_granted",
        "physical_device_verified",
        "dut_identity_verified",
        "calibration_verified",
        "physical_timing_verified",
        "simultaneous_measurements_verified",
        "energy_measured",
        "report_authenticated",
        "recorded_paths_followed",
        "instrument_state_current_verified",
    ),
    False,
)
FLAGS = {
    **NATIVE_FLAGS,
    "native_recomputed_now": False,
    "source_execution_performed": False,
    "native_scpi_replay_performed": False,
}


class EvidenceError(ValueError):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def require(condition, message, code="INVALID_INPUT"):
    if not condition:
        raise EvidenceError(message, code)


def fields(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "invalid load evidence fields")


def canonical(value):
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    require(len(raw) <= MAX_BUNDLE, "load document exceeds 16 MiB", "LIMIT_EXCEEDED")
    return raw


def same(left, right, message="load evidence differs"):
    require(canonical(left) == canonical(right), message, "EVIDENCE_MISMATCH")


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON field")
            value[key] = item
        return value

    def nonfinite(_):
        require(False, "nonfinite JSON")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 32, "load JSON depth exceeds 32")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, float):
            require(math.isfinite(item), "nonfinite JSON value")
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, "invalid load integer")
    return value


def number(value, low=0, high=1e30):
    require(
        type(value) in (int, float) and low <= value <= high and math.isfinite(value),
        "invalid load number",
    )
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def label(path):
    require(
        type(path) is str and 0 < len(path) <= 4096 and all(ord(c) >= 32 for c in path),
        "invalid recorded path label",
    )


def relative(path):
    label(path)
    require(
        len(path) <= 1024 and "\\" not in path and ":" not in path,
        "portable relative path required",
    )
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        p + str(i) for p in ("COM", "LPT") for i in range(1, 10)
    }
    require(
        all(
            p not in ("", ".", "..")
            and not p.endswith((" ", "."))
            and not any(c in '<>"|?*' for c in p)
            and p.split(".")[0].upper() not in reserved
            for p in path.split("/")
        ),
        "unsafe relative load path",
    )


def hash_value(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value), "invalid SHA-256")


def unpack(blob, limit, *, empty=False):
    fields(blob, ("path", "sha256", "size_bytes", "raw_base64"))
    label(blob["path"])
    size = integer(blob["size_bytes"], 0 if empty else 1, limit)
    hash_value(blob["sha256"])
    encoded = blob["raw_base64"]
    require(
        type(encoded) is str and len(encoded) == 4 * ((size + 2) // 3),
        "invalid embedded byte length",
    )
    raw = base64.b64decode(encoded, validate=True)
    require(
        len(raw) == size
        and digest(raw) == blob["sha256"]
        and base64.b64encode(raw).decode("ascii") == encoded,
        "embedded bytes differ",
        "EVIDENCE_MISMATCH",
    )
    return raw


def reference(value, blob):
    fields(value, ("path", "sha256", "size_bytes"))
    label(value["path"])
    same(
        {k: value[k] for k in ("sha256", "size_bytes")},
        {k: blob[k] for k in ("sha256", "size_bytes")},
        "native input binding differs",
    )
    return value


def validate_manifest(value):
    fields(value, ("schema_version", "native_exit_code", "inputs"))
    require(
        value["schema_version"] == "embedded-hil-runner.load-spec.v1",
        "unsupported load import spec",
    )
    integer(value["native_exit_code"], 0, 3)
    require(value["native_exit_code"] in (0, 3), "native JUnit must complete with exit 0 or 3")
    fields(value["inputs"], LIMITS)
    names = set()
    for item in value["inputs"].values():
        fields(item, ("path", "sha256"))
        relative(item["path"])
        hash_value(item["sha256"])
        require(item["path"].casefold() not in names, "duplicate load input path")
        names.add(item["path"].casefold())


def validate_contract(value):
    fields(value, ("schema_version", "checks"))
    require(
        value["schema_version"] == "lab-instruments.load-check-spec.v1",
        "unsupported native load spec",
    )
    checks = value["checks"]
    require(isinstance(checks, list) and 1 <= len(checks) <= 8, "expected 1..8 load checks")
    names = set()
    for check in checks:
        fields(check, ("id", "phase", "window", "expect"))
        name = check["id"]
        require(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name)
            and name not in names,
            "invalid/duplicate check id",
        )
        names.add(name)
        require(check["phase"] in ("before_load", "loaded", "observe"), "unsupported load phase")
        window = check["window"]
        fields(window, ("start", "end_exclusive"))
        integer(window["start"], 0, 49)
        integer(window["end_exclusive"], window["start"] + 1, 50)
        expect = check["expect"]
        require(
            isinstance(expect, dict) and bool(expect) and set(expect) <= {*METRICS, "input_on"},
            "unsupported expectations",
        )
        for metric, bounds in expect.items():
            if metric == "input_on":
                require(type(bounds) is bool, "input state must be boolean")
            else:
                fields(bounds, ("minimum", "maximum"))
                number(bounds["minimum"])
                number(bounds["maximum"], bounds["minimum"])


def raw_query(query, transcript, expected_command, value, cache):
    fields(query, ("transaction", "command", "transcript_span", "tx_sha256", "rx_base64"))
    integer(query["transaction"], 0, 999)
    same(query["command"], expected_command)
    span = query["transcript_span"]
    fields(span, ("start", "end_exclusive", "sha256"))
    start = integer(span["start"], 0, len(transcript) - 1)
    end = integer(span["end_exclusive"], start + 1, len(transcript))
    require(
        (start == 0 or transcript[start - 1 : start] == b"\n")
        and transcript[end - 1 : end] == b"\n",
        "query span is not whole records",
    )
    raw = transcript[start:end]
    same(digest(raw), span["sha256"], "raw query span hash differs")
    if "transactions" not in cache:
        transactions = {}
        offset = 0
        for line in transcript.splitlines(keepends=True):
            event = decode(line)
            if event["kind"] == "command.begin":
                transactions[offset] = len(transactions)
            offset += len(line)
        require(len(transactions) <= 1000, "too many saved transactions")
        cache["transactions"] = transactions
    same(query["transaction"], cache["transactions"].get(start), "transaction index differs")
    key = (start, end, expected_command)
    if key not in cache:
        events = [decode(line) for line in raw.splitlines()]
        require(4 <= len(events) <= 1024, "invalid query record count")
        require(
            events[0]["kind"] == "command.begin" and events[-1]["kind"] == "response.complete",
            "query framing differs",
        )
        same(events[0]["command"], expected_command)
        same(events[0]["cleanup"], False)
        tx, rx = bytearray(), bytearray()
        for event in events[1:-1]:
            require(event["kind"] in ("tx", "rx"), "unexpected query record")
            data = base64.b64decode(event["raw_base64"], validate=True)
            integer(event["bytes"], 1, 512)
            same(len(data), event["bytes"])
            if event["kind"] == "tx":
                require(not rx, "TX after RX")
                tx.extend(data)
            else:
                rx.extend(data)
        require(
            bytes(tx) == (expected_command + "\n").encode("ascii")
            and 0 < len(rx) <= 512
            and rx.endswith(b"\n")
            and b"\n" not in rx[:-1],
            "query bytes differ",
        )
        text = bytes(rx[:-1]).removesuffix(b"\r").decode("ascii")
        same((events[-1]["command"], events[-1]["response"]), (expected_command, text))
        cache[key] = (digest(tx), base64.b64encode(rx).decode("ascii"), number(float(text)))
    tx_hash, rx_base64, actual = cache[key]
    same(
        (query["tx_sha256"], query["rx_base64"], value),
        (tx_hash, rx_base64, actual),
        "raw query/value binding differs",
    )


def validate_report(report, contract, blobs, raw):
    fields(
        report,
        (
            "schema_version",
            "runner_version",
            "scope",
            "spec",
            "capture",
            "source",
            "input_files",
            "checks",
            "ok",
            "status",
            "complete",
            "summary",
            *NATIVE_FLAGS,
        ),
    )
    require(
        report["schema_version"] == "lab-instruments.load-check-report.v1"
        and report["runner_version"] == "0.10.0"
        and report["complete"] is True
        and report["scope"] == "host_only_saved_load_evaluation",
        "unsupported native load report",
    )
    same({k: report[k] for k in NATIVE_FLAGS}, NATIVE_FLAGS, "native qualification upgraded")
    validate_contract(contract)
    for role in ("spec", "capture"):
        reference(report[role], blobs[role])
    same(
        report["input_files"],
        [
            dict(name=name, **{k: blobs[role][k] for k in ("sha256", "size_bytes")})
            for role, name in (
                ("capture", "capture"),
                ("transcript", "transcript.jsonl"),
                ("plan", "plan.json"),
            )
        ],
        "native source inventory differs",
    )
    capture, plan = decode(raw["capture"]), decode(raw["plan"])
    require(
        capture["schema_version"] == "lab-instruments.load-result.v1"
        and plan["schema_version"] == "lab-instruments.load-plan.v1"
        and plan["model"] == "SDL1020X-E",
        "unsupported native load source",
    )
    same(capture["plan"], plan, "source plan differs")
    same(capture["plan_sha256"], digest(canonical(plan)), "plan digest differs")
    same(capture["transcript"], {k: blobs["transcript"][k] for k in ("sha256", "size_bytes")})
    require(
        capture["time_semantics"] == "host_query_windows_not_simultaneous_instrument_samples",
        "source time basis differs",
    )
    require(
        type(capture["ok"]) is bool
        and capture["status"] == ("completed" if capture["ok"] else "failed"),
        "source status differs",
    )
    require(
        type(plan["test_double"]) is bool and type(capture["hardware_access"]) is bool,
        "invalid source boolean",
    )
    require(
        capture["evidence_origin"]
        == ("test_double" if plan["test_double"] else "scpi_tcp_session"),
        "source origin differs",
    )
    require(
        not plan["test_double"] or capture["hardware_access"] is False,
        "synthetic source claims hardware",
    )
    for flag in (
        "physical_device_verified",
        "exclusive_instrument_ownership_verified",
        "dut_identity_verified",
        "calibration_verified",
        "authorization_granted",
    ):
        require(capture[flag] is False, "source qualification upgraded")
    require(
        plan["authorization_granted"] is False
        and plan["hardware_identity_verified"] is False
        and type(plan["retries"]) is int
        and plan["retries"] == 0,
        "source grants authority/retries",
    )
    action = plan["action"]
    require(action in ("cc", "observe", "identify", "off"), "unsupported source action")
    samples = capture["measurements"]
    require(isinstance(samples, list) and len(samples) <= 50, "invalid source measurement count")
    cleanup = capture["cleanup"]
    require(not capture["ok"] or bool(raw["transcript"]), "successful source has empty transcript")
    for flag in (
        "off_attempted",
        "off_transmitted",
        "input_off_confirmed",
        "socket_closed",
        "local_lease_released",
        "complete",
    ):
        require(type(cleanup[flag]) is bool, "invalid cleanup flag")
    if capture["ok"]:
        require(
            cleanup["complete"]
            and cleanup["socket_closed"]
            and cleanup["local_lease_released"]
            and cleanup["errors"] == []
            and "error" not in capture,
            "source cleanup incomplete",
        )
        owned = action in ("cc", "off")
        same(
            (cleanup["off_attempted"], cleanup["off_transmitted"], cleanup["input_off_confirmed"]),
            (owned, owned, owned),
        )
        same(cleanup["instrument_state"], "input_off_reported" if owned else "not_established")
        same(
            (capture["configuration_attempted"], capture["input_enable_attempted"]),
            (action == "cc", action == "cc"),
        )
        if action in ("cc", "observe"):
            integer(plan["samples"], 1, 50)
            same(len(samples), plan["samples"])
    else:
        fields(capture["error"], ("code", "message"))
        require(
            all(type(v) is str and len(v) <= 512 for v in capture["error"].values()),
            "invalid source error",
        )
    expected_source = dict(
        source_status=capture["status"],
        source_ok=capture["ok"],
        source_success_replayed=capture["ok"],
        source_error=capture.get("error"),
        recorded_cleanup=cleanup,
        recorded_identity=capture.get("identity"),
        evidence_origin=capture["evidence_origin"],
        action=action,
        recorded_effects={
            k: capture[k]
            for k in ("hardware_access", "input_enable_attempted", "configuration_attempted")
        },
        time_semantics=TIME,
        source_measurements_simultaneous=False,
        failed_source_measurements_evaluated=False,
        recorded_partial_measurements=samples if not capture["ok"] else [],
    )
    same(report["source"], expected_source, "recorded source context differs")
    phases = dict(before_load=[], loaded=[], observe=[])
    if capture["ok"]:
        if action == "cc":
            phases["before_load"] = [capture["preflight"]["baseline"]]
        if action in ("cc", "observe"):
            phases["loaded" if action == "cc" else "observe"] = samples
    checks = report["checks"]
    require(
        isinstance(checks, list) and len(checks) == len(contract["checks"]),
        "native check count differs",
    )
    query_cache = {}
    for check, selected in zip(checks, contract["checks"], strict=True):
        same(
            {k: check[k] for k in ("id", "phase", "window", "expect")},
            selected,
            "check spec differs",
        )
        phase = phases[selected["phase"]]
        start, stop = selected["window"]["start"], selected["window"]["end_exclusive"]
        reason = (
            "source_failed"
            if not capture["ok"]
            else "phase_unavailable"
            if not phase
            else "window_unavailable"
            if stop > len(phase)
            else None
        )
        if reason:
            same(
                check,
                {
                    **selected,
                    "status": "invalid_evidence",
                    "ok": False,
                    "reason": reason,
                    "metrics": None,
                    "assertions": [],
                    "measurements": [],
                },
                "invalid source upgraded",
            )
            continue
        fields(check, (*selected, "status", "ok", "metrics", "assertions", "measurements"))
        require(
            isinstance(check["measurements"], list) and len(check["measurements"]) == stop - start,
            "window samples differ",
        )
        for position, (observed, original) in enumerate(
            zip(check["measurements"], phase[start:stop], strict=True), start
        ):
            same(
                {k: v for k, v in observed.items() if k not in ("input_on", "raw_queries")},
                {k: v for k, v in original.items() if k != "input_on"},
                "selected source sample differs",
            )
            expected_index = -1 if selected["phase"] == "before_load" else position
            require(
                type(observed["index"]) is int
                and observed["index"] == expected_index
                and observed["phase"] == selected["phase"],
                "phase/index differs",
            )
            state = False if selected["phase"] == "before_load" else original["input_on"]
            require(type(state) is bool, "invalid input state")
            same(observed["input_on"], state)
            queries = observed["raw_queries"]
            require(isinstance(queries, list) and len(queries) == 3, "missing raw query provenance")
            for quantity, command, query in zip(
                QUANTITIES, ("MEAS:VOLT:DC?", "MEAS:CURR:DC?", "MEAS:POW:DC?"), queries, strict=True
            ):
                number(observed[quantity])
                raw_query(query, raw["transcript"], command, observed[quantity], query_cache)
        metrics = {}
        for quantity in QUANTITIES:
            values = [s[quantity] for s in phase[start:stop]]
            metrics.update(
                {
                    "minimum_" + quantity: min(values),
                    "maximum_" + quantity: max(values),
                    "mean_" + quantity: math.fsum(values) / len(values),
                }
            )
        same(check["metrics"], metrics, "recorded metric consistency differs")
        assertions = []
        for metric, expected in sorted(selected["expect"].items()):
            actual = (
                [s["input_on"] for s in check["measurements"]]
                if metric == "input_on"
                else metrics[metric]
            )
            passed = (
                all(v is expected for v in actual)
                if metric == "input_on"
                else expected["minimum"] <= actual <= expected["maximum"]
            )
            assertions.append(dict(metric=metric, expected=expected, actual=actual, ok=passed))
        same(check["assertions"], assertions, "recorded comparisons differ")
        passed = all(a["ok"] for a in assertions)
        same((check["ok"], check["status"]), (passed, "passed" if passed else "failed"))
    summary = dict(
        checks=len(checks),
        **{
            s: sum(c["status"] == s for c in checks)
            for s in ("passed", "failed", "invalid_evidence")
        },
    )
    same(report["summary"], summary)
    passed = summary["passed"] == len(checks)
    same((report["ok"], report["status"]), (passed, "passed" if passed else "failed"))


def project(manifest_blob, blobs, version):
    require(version == "0.11.0", "unsupported HIL load producer")
    manifest = decode(unpack(manifest_blob, MAX_MANIFEST))
    validate_manifest(manifest)
    fields(blobs, LIMITS)
    raw = {r: unpack(blobs[r], limit, empty=r == "transcript") for r, limit in LIMITS.items()}
    for role, item in manifest["inputs"].items():
        same(item["sha256"], blobs[role]["sha256"])
    report, contract, response = (decode(raw[r]) for r in ("report", "spec", "native_result"))
    validate_report(report, contract, blobs, raw)
    fields(
        response,
        (
            "schema_version",
            "ok",
            "data",
            "hardware_access",
            "executables_started",
            "authorization_granted",
            "physical_device_verified",
            "outputs_commanded",
        ),
    )
    require(
        response["schema_version"] == "lab-instruments.result.v1", "unsupported native response"
    )
    for flag in (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "outputs_commanded",
    ):
        require(response[flag] is False, "native response qualification upgraded")
    same(response["ok"], report["ok"])
    same(manifest["native_exit_code"], 0 if report["ok"] else 3)
    fields(response["data"], ("verification", "junit", "output"))
    verified = response["data"]["verification"]
    bindings = {}
    for role in ("spec", "capture"):
        supplied = reference(verified["bindings"][role]["supplied"], blobs[role])
        bindings[role] = dict(
            recorded=report[role],
            supplied=supplied,
            path_label_differs=report[role]["path"] != supplied["path"],
        )
    same(
        verified,
        dict(
            schema_version="lab-instruments.load-check-verification.v1",
            ok=True,
            status="verified",
            complete=True,
            report=reference(verified["report"], blobs["report"]),
            bindings=bindings,
            producer_runner_version="0.10.0",
            verifier_version="0.10.0",
            verdict={k: report[k] for k in ("ok", "status", "summary")},
            scope="host_only_saved_load_verification",
            **NATIVE_FLAGS,
        ),
        "native verification differs",
    )
    counts = dict(
        tests=len(report["checks"]),
        failures=report["summary"]["failed"],
        errors=report["summary"]["invalid_evidence"],
        skipped=0,
    )
    same(response["data"]["junit"], counts)
    reference(response["data"]["output"], blobs["junit"])
    return dict(
        schema_version="embedded-hil-runner.load-report.v1",
        producer_version=version,
        scope="host_only_saved_load_import",
        **FLAGS,
        ok=report["ok"],
        status=report["status"],
        summary=report["summary"],
        source=report["source"],
        checks=report["checks"],
        native_exit_code=manifest["native_exit_code"],
        native_recomputation_recorded=True,
        validation_kind="recorded_native_verification_and_explicit_input_integrity",
        junit=counts,
        import_spec=manifest_blob,
        inputs=blobs,
    )
