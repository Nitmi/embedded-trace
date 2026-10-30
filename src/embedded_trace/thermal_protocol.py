"""Thermal evidence consistency, vendored identically in HIL and Trace.

Only recorded bindings, metadata, comparisons and trend arithmetic are checked.
No file I/O, temperature conversion, native imports or XML reconstruction.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re

MAX_BUNDLE = 32 * 1024 * 1024
MAX_MANIFEST = 256 * 1024
MAX_SOURCES = 16 * 1024 * 1024
LIMITS = dict(report=1048576, spec=65536, capture=1048576, native_result=131072, junit=1048576)
TIME = "sensor_uptime_no_verified_utc_or_physical_clock"
TEMPERATURES = ("min_c", "max_c", "mean_c", "p95_c")
DELTAS = ("mean_delta_c", "max_delta_c")
NATIVE_FLAGS = dict.fromkeys(
    (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "dut_identity_verified",
        "calibration_verified",
        "radiometric_accuracy_verified",
        "physical_timing_verified",
        "scene_parameters_verified",
        "junction_temperature_verified",
        "report_authenticated",
        "recorded_paths_followed",
    ),
    False,
)
FLAGS = {
    **NATIVE_FLAGS,
    "native_recomputed_now": False,
    "source_execution_performed": False,
    "native_temperature_conversion_performed": False,
}


class EvidenceError(ValueError):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def require(value, message, code="INVALID_INPUT"):
    if not value:
        raise EvidenceError(message, code)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "invalid thermal evidence fields")


def canonical(value):
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    require(len(raw) <= MAX_BUNDLE, "thermal document exceeds 32 MiB", "LIMIT_EXCEEDED")
    return raw


def same(actual, expected, message="thermal evidence differs"):
    require(canonical(actual) == canonical(expected), message, "EVIDENCE_MISMATCH")


def decode(raw):
    def unique(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON field")
            value[key] = item
        return value

    def bad(_):
        require(False, "nonfinite JSON")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=bad)
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 32, "thermal JSON depth exceeds 32")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, float):
            require(math.isfinite(item), "nonfinite JSON")
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, "invalid thermal integer")
    return value


def number(value, low=-410, high=410):
    require(
        type(value) in (int, float) and low <= value <= high and math.isfinite(value),
        "invalid thermal number",
    )
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_value(value):
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value), "invalid SHA-256")


def label(value):
    require(
        type(value) is str and 0 < len(value) <= 4096 and all(ord(c) >= 32 for c in value),
        "invalid path label",
    )


def relative(value):
    label(value)
    require(
        len(value) <= 1024 and "\\" not in value and ":" not in value,
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
            for p in value.split("/")
        ),
        "unsafe relative path",
    )


def source_name(value):
    require(
        type(value) is str
        and re.fullmatch(r"(?:native/)?[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value)
        and value != "capture",
        "invalid thermal source name",
    )
    relative(value)
    return value


def unpack(blob, maximum, *, empty=False):
    fields(blob, ("path", "sha256", "size_bytes", "raw_base64"))
    label(blob["path"])
    size = integer(blob["size_bytes"], 0 if empty else 1, maximum)
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
    fields(value, ("schema_version", "native_exit_code", "inputs", "source_files"))
    require(
        value["schema_version"] == "embedded-hil-runner.thermal-spec.v1", "unsupported thermal spec"
    )
    integer(value["native_exit_code"], 0, 3)
    require(value["native_exit_code"] in (0, 3), "native JUnit must complete with exit 0 or 3")
    fields(value["inputs"], LIMITS)
    sources = value["source_files"]
    require(
        isinstance(sources, list) and 1 <= len(sources) <= 100, "expected 1..100 thermal sources"
    )
    names, paths = set(), set()
    for item in sources:
        fields(item, ("name", "path", "sha256"))
        source_name(item["name"])
        require(item["name"].casefold() not in names, "duplicate thermal source name")
        names.add(item["name"].casefold())
    for item in value["inputs"].values():
        fields(item, ("path", "sha256"))
    for item in [*value["inputs"].values(), *sources]:
        relative(item["path"])
        hash_value(item["sha256"])
        require(item["path"].casefold() not in paths, "duplicate input path")
        paths.add(item["path"].casefold())


def rectangle(value):
    fields(value, ("x", "y", "width", "height"))
    integer(value["x"], 0, 159)
    integer(value["y"], 0, 119)
    integer(value["width"], 1, 160 - value["x"])
    integer(value["height"], 1, 120 - value["y"])


def contains(outer, inner):
    return all(
        outer[k] <= inner[k] and inner[k] + inner[s] <= outer[k] + outer[s]
        for k, s in (("x", "width"), ("y", "height"))
    )


def validate_contract(value):
    fields(value, ("schema_version", "checks"))
    require(
        value["schema_version"] == "lab-instruments.thermal-check-spec.v1",
        "unsupported native spec",
    )
    require(
        isinstance(value["checks"], list) and 1 <= len(value["checks"]) <= 8, "expected 1..8 checks"
    )
    names = set()
    for c in value["checks"]:
        fields(c, ("id", "roi", "window", "maximum_invalid_pixels", "expect"))
        require(
            type(c["id"]) is str
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}", c["id"])
            and c["id"] not in names,
            "invalid/duplicate check id",
        )
        names.add(c["id"])
        rectangle(c["roi"])
        integer(c["maximum_invalid_pixels"], 0, c["roi"]["width"] * c["roi"]["height"] - 1)
        fields(c["window"], ("start", "end_exclusive"))
        integer(c["window"]["start"], 0, 7)
        integer(c["window"]["end_exclusive"], c["window"]["start"] + 1, 8)
        expect = c["expect"]
        require(
            isinstance(expect, dict)
            and bool(expect)
            and set(expect) <= {*TEMPERATURES, *DELTAS, "hotspot_within"},
            "invalid expectations",
        )
        for key, bounds in expect.items():
            if key == "hotspot_within":
                rectangle(bounds)
                require(contains(c["roi"], bounds), "hotspot rectangle exceeds ROI")
            else:
                fields(bounds, ("minimum", "maximum"))
                low, high = (-410, 410) if key in DELTAS else (-10, 400)
                number(bounds["minimum"], low, high)
                number(bounds["maximum"], bounds["minimum"], high)


def source_context(capture, sources, raw_sources):
    require(
        capture["schema_version"] == "lab-instruments.thermal-result.v1",
        "unsupported thermal capture",
    )
    plan = capture["plan"]
    require(
        plan["schema_version"] == "lab-instruments.thermal-plan.v1"
        and plan["action"] == "capture"
        and type(plan["test_double"]) is bool
        and type(capture["ok"]) is bool,
        "invalid source capture",
    )
    same(capture["status"], "completed" if capture["ok"] else "failed")
    same(capture["plan_sha256"], digest(canonical(plan)))
    same(decode(raw_sources["plan.json"]), plan)
    for key in (
        "physical_device_verified",
        "calibration_verified",
        "authorization_granted",
        "outputs_commanded",
    ):
        require(capture[key] is False, "source qualification upgraded")
    require(capture["operation"] in ("run", "import"), "invalid source operation")
    fields(capture["artifacts"], sources)
    for name, blob in sources.items():
        same(capture["artifacts"][name], {k: blob[k] for k in ("sha256", "size_bytes")})
    native = (
        decode(raw_sources["native/native.json"]) if "native/native.json" in raw_sources else None
    )
    origin = "test_double" if plan["test_double"] else "windows_media_foundation"
    if capture["ok"]:
        require(
            native["ok"] is True
            and native["cleanup_complete"] is True
            and not native["error"]
            and native["capture_started"] is True
            and native["origin"] == origin,
            "source native cleanup/status differs",
        )
        same(native["link"], plan["link"])
        if capture["operation"] == "run":
            require(
                capture["cleanup_complete"] is True
                and capture["local_lease_released"] is True
                and capture["executables_started"] is True
                and capture["hardware_access"] is (not plan["test_double"]),
                "source cleanup/effects differ",
            )
        else:
            require(
                capture["executables_started"] is False and capture["hardware_access"] is False,
                "source import claims execution",
            )
        declared = decode(raw_sources["native/source.json"])
        require(
            declared["schema_version"] == "lab-instruments.thermal-source.v1",
            "invalid native inventory",
        )
        same(declared["plan_sha256"], capture["plan_sha256"])
        expected = {
            n.removeprefix("native/"): {k: sources[n][k] for k in ("sha256", "size_bytes")}
            for n in sources
            if n.startswith("native/")
            and n not in ("native/source.json", "native/helper.stdout", "native/helper.stderr")
        }
        same(declared["files"], expected, "native raw inventory differs")
        frames = capture["analysis"]["frames"]
        integer(plan["buffers"], 1, 8)
        same(len(frames), plan["buffers"])
        same(len(native["frames"]), len(frames))
        require(capture["analysis"]["source_origin"] == origin, "source analysis origin differs")
        for flag in (
            "radiometric_accuracy_verified",
            "physical_device_verified",
            "dut_identity_verified",
            "calibration_verified",
            "authorization_granted",
        ):
            require(capture["analysis"][flag] is False, "source analysis qualification upgraded")
        previous = -1
        for i, f in enumerate(frames):
            name = f"frame-{i:04d}.y16"
            same(f["raw_sha256"], sources["native/" + name]["sha256"])
            same(len(raw_sources["native/" + name]), 39040)
            same(native["frames"][i], dict(name=name, timestamp_100ns=f["native_timestamp_100ns"]))
            previous = integer(f["native_timestamp_100ns"], previous + 1, 2**63 - 1)
            same(
                f["csv"],
                dict(
                    name=f"frame-{i:04d}.csv",
                    **{k: sources[f"frame-{i:04d}.csv"][k] for k in ("sha256", "size_bytes")},
                ),
            )
    return dict(
        source_ok=capture["ok"],
        source_status=capture["status"],
        source_error=capture.get("error"),
        operation=capture["operation"],
        evidence_origin=origin,
        source_cleanup=dict(
            recorded_parent_cleanup_complete=capture.get("cleanup_complete"),
            recorded_lease_released=capture.get("local_lease_released"),
            native=native,
        ),
        recorded_effects=plan["effects"],
        source_hardware_access=capture["hardware_access"],
        source_executables_started=capture["executables_started"],
        context=plan["context"],
        analysis=capture.get("analysis") if capture["ok"] else None,
        time_basis=TIME,
        apparent_surface_temperature_only=True,
        hotspot_tie_policy="first_maximum_in_row_major_roi_order",
        p95_definition="nearest_rank_ceil_0.95_n_valid_pixels",
        partial_frames_scored=False,
    )


def recorded_trend(rows):
    unique, duplicates = [], 0
    for row in rows:
        if unique and row["telemetry"]["frame_counter"] == unique[-1]["telemetry"]["frame_counter"]:
            same(
                row["raw_sha256"],
                unique[-1]["raw_sha256"],
                "duplicate counter has different raw bytes",
            )
            duplicates += 1
            continue
        if unique:
            prev, current = unique[-1]["telemetry"], row["telemetry"]
            require(
                current["frame_counter"] > prev["frame_counter"]
                and current["uptime_ms"] > prev["uptime_ms"],
                "counter/uptime reversed",
            )
        unique.append(row)
    compatible = (
        len(unique) > 1
        and len(
            {
                (
                    r["telemetry"]["last_ffc_ms"],
                    r["telemetry"]["effective_gain"],
                    r["telemetry"]["resolution"],
                    r["roi"]["valid_mask_sha256"],
                )
                for r in unique
            }
        )
        == 1
    )
    changes = []
    if compatible:
        before, after = unique[0], unique[-1]
        changes = [
            dict(
                name=before["roi"]["name"],
                elapsed_sensor_s=(
                    after["telemetry"]["uptime_ms"] - before["telemetry"]["uptime_ms"]
                )
                / 1000,
                mean_delta_c=after["roi"]["mean_c"] - before["roi"]["mean_c"],
                max_delta_c=after["roi"]["max_c"] - before["roi"]["max_c"],
            )
        ]
    return dict(
        unique_frames=len(unique),
        duplicate_buffers=duplicates,
        temperature_trend_supported=compatible,
        roi_changes=changes,
    )


def validate_check(check, selected, info):
    fields(check, (*selected, "status", "ok", "reason", "frames", "trend", "assertions"))
    same({k: check[k] for k in selected}, selected)
    rows = check["frames"]
    require(isinstance(rows, list) and len(rows) <= 8, "invalid recorded frame rows")
    start, stop = selected["window"]["start"], selected["window"]["end_exclusive"]
    reason = (
        "source_failed"
        if not info["source_ok"]
        else ("window_unavailable" if stop > len(info["analysis"]["frames"]) else None)
    )
    if reason:
        same((rows, check["trend"], check["assertions"]), ([], None, []))
    else:
        roi = selected["roi"]
        area = roi["width"] * roi["height"]
        require(len(rows) <= stop - start, "too many frame rows")
        for index, row in enumerate(rows, start):
            fields(
                row,
                (
                    "buffer_index",
                    "raw_sha256",
                    "pixel_encoding",
                    "raw_roi_span",
                    "native_timestamp_100ns",
                    "telemetry",
                    "roi",
                ),
            )
            original = info["analysis"]["frames"][index]
            same(row["buffer_index"], index)
            for key in ("raw_sha256", "native_timestamp_100ns", "telemetry"):
                same(row[key], original[key])
            same(row["pixel_encoding"], "uint16_le_row_major_160x120_with_160x2_footer")
            same(
                row["raw_roi_span"],
                dict(
                    first_byte=2 * (roi["y"] * 160 + roi["x"]),
                    row_stride_bytes=320,
                    row_bytes=2 * roi["width"],
                    rows=roi["height"],
                ),
            )
            r = row["roi"]
            fields(
                r,
                (
                    "name",
                    "valid_pixels",
                    "invalid_or_out_of_range_pixels",
                    *TEMPERATURES,
                    "hotspot",
                    "small_roi",
                    "valid_mask_sha256",
                ),
            )
            same(r["name"], selected["id"])
            integer(r["valid_pixels"], 1, area)
            same(r["invalid_or_out_of_range_pixels"], area - r["valid_pixels"])
            same(r["small_roi"], area < 10)
            hash_value(r["valid_mask_sha256"])
            for key in TEMPERATURES:
                number(r[key], -10, 400)
            require(
                math.nextafter(r["min_c"], -math.inf)
                <= r["mean_c"]
                <= math.nextafter(r["max_c"], math.inf)
                and r["min_c"] <= r["p95_c"] <= r["max_c"],
                "recorded ROI statistics inconsistent",
            )
            fields(r["hotspot"], ("x", "y"))
            integer(r["hotspot"]["x"], 0, 159)
            integer(r["hotspot"]["y"], 0, 119)
            require(contains(roi, {**r["hotspot"], "width": 1, "height": 1}), "hotspot outside ROI")
            if r["invalid_or_out_of_range_pixels"] > selected["maximum_invalid_pixels"]:
                reason = "invalid_pixel_budget_exceeded"
        if len(rows) < stop - start:
            same(check["reason"], "no_valid_pixels")
            reason = "no_valid_pixels"
        if not reason:
            trend = recorded_trend(rows)
            same(check["trend"], trend)
            if (
                any(k in selected["expect"] for k in DELTAS)
                and not trend["temperature_trend_supported"]
            ):
                reason = "trend_unavailable"
        elif reason in ("no_valid_pixels", "invalid_pixel_budget_exceeded"):
            same(check["trend"], None)
    if reason:
        same(
            (check["status"], check["ok"], check["reason"], check["assertions"]),
            ("invalid_evidence", False, reason, []),
        )
        return
    assertions = []
    for key, bounds in sorted(selected["expect"].items()):
        actual = (
            [check["trend"]["roi_changes"][0][key]]
            if key in DELTAS
            else [r["roi"]["hotspot" if key == "hotspot_within" else key] for r in rows]
        )
        ok = all(
            contains(bounds, {**v, "width": 1, "height": 1})
            if key == "hotspot_within"
            else bounds["minimum"] <= v <= bounds["maximum"]
            for v in actual
        )
        assertions.append(dict(metric=key, expected=bounds, actual=actual, ok=ok))
    ok = all(a["ok"] for a in assertions)
    same(check["assertions"], assertions)
    same((check["ok"], check["status"], check["reason"]), (ok, "passed" if ok else "failed", None))


def project(manifest_blob, blobs, source_blobs, version):
    require(version in ("0.12.0", "0.13.0", "0.14.0"), "unsupported HIL thermal producer")
    manifest = decode(unpack(manifest_blob, MAX_MANIFEST))
    validate_manifest(manifest)
    fields(blobs, LIMITS)
    fields(source_blobs, [item["name"] for item in manifest["source_files"]])
    # Enforce aggregate source budget before base64 decoding.
    total = integer(blobs["capture"]["size_bytes"], 1, LIMITS["capture"])
    for blob in source_blobs.values():
        total += integer(blob["size_bytes"], 0, 1048576)
    require(total <= MAX_SOURCES, "thermal source budget exceeds 16 MiB", "LIMIT_EXCEEDED")
    raw = {role: unpack(blobs[role], maximum) for role, maximum in LIMITS.items()}
    raw_sources = {
        name: unpack(source_blobs[name], 1048576, empty=True)
        for name in (item["name"] for item in manifest["source_files"])
    }
    for role, item in manifest["inputs"].items():
        same(item["sha256"], blobs[role]["sha256"])
    for item in manifest["source_files"]:
        same(item["sha256"], source_blobs[item["name"]]["sha256"])
    report, contract, capture, response = (
        decode(raw[r]) for r in ("report", "spec", "capture", "native_result")
    )
    validate_contract(contract)
    fields(
        report,
        (
            "schema_version",
            "runner_version",
            "scope",
            "spec",
            "capture",
            "source",
            "checks",
            "ok",
            "status",
            "complete",
            "summary",
            "input_files",
            *NATIVE_FLAGS,
        ),
    )
    require(
        report["schema_version"] == "lab-instruments.thermal-check-report.v1"
        and report["runner_version"] == "0.11.0"
        and report["complete"] is True
        and report["scope"] == "host_only_saved_thermal_assertions",
        "unsupported native thermal report",
    )
    same({k: report[k] for k in NATIVE_FLAGS}, NATIVE_FLAGS)
    for role in ("spec", "capture"):
        reference(report[role], blobs[role])
    inventory = [dict(name="capture", **{k: blobs["capture"][k] for k in ("sha256", "size_bytes")})]
    inventory += [
        dict(
            name=item["name"],
            **{k: source_blobs[item["name"]][k] for k in ("sha256", "size_bytes")},
        )
        for item in manifest["source_files"]
    ]
    same(report["input_files"], inventory, "native explicit source inventory differs")
    info = source_context(capture, source_blobs, raw_sources)
    same(report["source"], info)
    require(
        isinstance(report["checks"], list) and len(report["checks"]) == len(contract["checks"]),
        "check count differs",
    )
    for check, selected in zip(report["checks"], contract["checks"], strict=True):
        validate_check(check, selected, info)
    summary = dict(
        checks=len(report["checks"]),
        **{
            s: sum(c["status"] == s for c in report["checks"])
            for s in ("passed", "failed", "invalid_evidence")
        },
    )
    ok = all(c["ok"] for c in report["checks"])
    same(
        (report["ok"], report["status"], report["summary"]),
        (ok, "passed" if ok else "failed", summary),
    )
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
    same(response["schema_version"], "lab-instruments.result.v1")
    for flag in (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "outputs_commanded",
    ):
        require(response[flag] is False, "native response qualification upgraded")
    same(response["ok"], ok)
    same(manifest["native_exit_code"], 0 if ok else 3)
    fields(response["data"], ("verification", "junit", "output"))
    verified = response["data"]["verification"]
    fields(verified["bindings"], ("spec", "capture"))
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
            schema_version="lab-instruments.thermal-check-verification.v1",
            ok=True,
            status="verified",
            complete=True,
            report=reference(verified["report"], blobs["report"]),
            bindings=bindings,
            producer_runner_version="0.11.0",
            verifier_version="0.11.0",
            verdict={k: report[k] for k in ("ok", "status", "summary")},
            scope="host_only_saved_thermal_verification",
            **NATIVE_FLAGS,
        ),
    )
    counts = dict(
        tests=len(report["checks"]),
        failures=summary["failed"],
        errors=summary["invalid_evidence"],
        skipped=0,
    )
    same(response["data"]["junit"], counts)
    reference(response["data"]["output"], blobs["junit"])
    return dict(
        schema_version="embedded-hil-runner.thermal-report.v1",
        producer_version=version,
        scope="host_only_saved_thermal_import",
        **FLAGS,
        ok=ok,
        status=report["status"],
        summary=summary,
        source=info,
        checks=report["checks"],
        native_exit_code=manifest["native_exit_code"],
        native_recomputation_recorded=True,
        validation_kind="recorded_native_verification_and_explicit_input_integrity",
        junit=counts,
        import_spec=manifest_blob,
        inputs=blobs,
        source_files=source_blobs,
    )
