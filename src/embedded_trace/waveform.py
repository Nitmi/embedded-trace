"""Offline views of saved HIL waveform bundles; no voltage conversion or wire replay."""

from __future__ import annotations

import base64
import json
import math
import re

from . import __version__
from .common import (
    digest,
    integer,
    parse_json,
    read_file,
    relative_source,
    require,
    write_new_bytes,
)
from .instrument import bound, same, unpack

MAX_BUNDLE = 20 * 1024 * 1024
LIMITS = dict(report=1048576, spec=65536, capture=1048576, native_result=131072, junit=1048576)
NATIVE_FLAGS = dict.fromkeys(
    (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "physical_timing_verified",
        "calibration_verified",
        "dut_identity_verified",
        "sample_zero_utc_verified",
        "cross_channel_alignment_verified",
        "clipping_absent_verified",
        "analog_bandwidth_verified",
        "report_authenticated",
        "recorded_paths_followed",
    ),
    False,
)
FLAGS = {**NATIVE_FLAGS, "native_recomputed_now": False, "source_execution_performed": False}


def canonical(value):
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    require(len(raw) <= MAX_BUNDLE, "waveform view exceeds 20 MiB", "LIMIT_EXCEEDED")
    return raw


def exact(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "invalid waveform fields")


def unpack_source(blob):
    if blob.get("size_bytes") == 0 and type(blob.get("size_bytes")) is int:
        exact(blob, ("path", "sha256", "size_bytes", "raw_base64"))
        require(
            type(blob["path"]) is str and 0 < len(blob["path"]) <= 4096, "invalid source path label"
        )
        same((blob["sha256"], blob["raw_base64"]), (digest(b""), ""), "empty source bytes differ")
        return b""
    return unpack(blob, 1048576)


def load(path, sha):
    raw, ref = read_file(path, MAX_BUNDLE, sha)
    bundle = parse_json(raw)
    exact(
        bundle,
        (
            "schema_version",
            "producer_version",
            "scope",
            "ok",
            "status",
            "summary",
            "source_kind",
            "source",
            "checks",
            "native_exit_code",
            "native_recomputation_recorded",
            "validation_kind",
            "junit",
            "import_spec",
            "inputs",
            "source_files",
            *FLAGS,
        ),
    )
    require(
        bundle["schema_version"] == "embedded-hil-runner.waveform-report.v1"
        and bundle["producer_version"] in ("0.10.0", "0.11.0", "0.12.0", "0.13.0")
        and bundle["scope"] == "host_only_saved_waveform_import"
        and bundle["native_recomputation_recorded"] is True
        and bundle["validation_kind"]
        == "recorded_native_verification_and_explicit_input_integrity",
        "unsupported HIL waveform report",
    )
    same({k: bundle[k] for k in FLAGS}, FLAGS, "waveform claims upgraded")
    manifest = parse_json(unpack(bundle["import_spec"], 512 * 1024))
    exact(manifest, ("schema_version", "native_exit_code", "inputs", "source_files"))
    require(
        manifest["schema_version"] == "embedded-hil-runner.waveform-spec.v1",
        "unsupported waveform import spec",
    )
    exact(manifest["inputs"], LIMITS)
    exact(bundle["inputs"], LIMITS)
    sources = manifest["source_files"]
    require(isinstance(sources, list) and len(sources) <= 1614, "too many waveform sources")
    source_blobs = bundle["source_files"]
    require(
        isinstance(source_blobs, dict)
        and len(source_blobs) == len(sources)
        and set(source_blobs) == {i["name"] for i in sources},
        "source inventory differs",
    )
    raw_inputs = {role: unpack(bundle["inputs"][role], limit) for role, limit in LIMITS.items()}
    paths = set()
    for item in [*manifest["inputs"].values(), *sources]:
        relative_source(path.parent, item["path"])  # Validate only; never follow these paths.
        require(item["path"].casefold() not in paths, "duplicate manifest input path")
        paths.add(item["path"].casefold())
    for role, selected in manifest["inputs"].items():
        exact(selected, ("path", "sha256"))
        same(selected["sha256"], bundle["inputs"][role]["sha256"], "manifest hash differs")
    inventory = [
        dict(
            name="capture", **{k: bundle["inputs"]["capture"][k] for k in ("sha256", "size_bytes")}
        )
    ]
    size = inventory[0]["size_bytes"]
    for item in sources:
        exact(item, ("name", "path", "sha256"))
        name = item["name"]
        require(
            type(name) is str
            and re.fullmatch(
                r"(?:plan\.json|transcript\.jsonl|wire-[0-9]{4}-(?:tx|rx)\.bin|"
                r"c[1-4]-(?:preamble\.bin|words\.bin|samples\.csv))",
                name,
            ),
            "invalid source file name",
        )
        blob = source_blobs[name]
        size += integer(blob["size_bytes"], "source bytes", 0, 1048576)
        require(size <= 8 * 1024 * 1024, "source budget exceeded", "LIMIT_EXCEEDED")
        unpack_source(blob)
        same(item["sha256"], blob["sha256"], "source manifest hash differs")
        inventory.append(dict(name=name, **{k: blob[k] for k in ("sha256", "size_bytes")}))
    report, contract, native = (
        parse_json(raw_inputs[k]) for k in ("report", "spec", "native_result")
    )
    require(
        report["schema_version"] == "lab-instruments.waveform-check-report.v1"
        and report["runner_version"] in ("0.9.0", "0.10.0", "0.11.0")
        and report["complete"] is True
        and report["scope"] == "host_only_saved_waveform_evaluation"
        and contract["schema_version"] == "lab-instruments.waveform-check-spec.v1",
        "unsupported native waveform evidence",
    )
    same({k: report[k] for k in NATIVE_FLAGS}, NATIVE_FLAGS, "native waveform claims upgraded")
    same(report["input_files"], inventory, "native source inventory differs")
    for role in ("spec", "capture"):
        bound(report[role], bundle["inputs"][role])
    capture = parse_json(raw_inputs["capture"])
    same(report["source"]["source_cleanup"], capture["cleanup"], "source cleanup differs")
    same(report["source"]["evidence_origin"], capture["evidence_origin"], "source origin differs")
    require(
        report["source_kind"] in ("ad3", "sds804x")
        and report["source_kind"] == contract["source_kind"],
        "invalid waveform source kind",
    )
    require(
        (report["source_kind"] == "ad3") == (not bool(sources)), "source inventory kind differs"
    )
    checks = report["checks"]
    require(
        isinstance(checks, list)
        and 1 <= len(checks) <= 8
        and len(checks) == len(contract["checks"]),
        "invalid native check count",
    )
    require(len({c["id"] for c in checks}) == len(checks), "duplicate native check id")
    for check, selected in zip(checks, contract["checks"], strict=True):
        same(
            {k: check[k] for k in ("id", "channel", "window", "expect")},
            selected,
            "native waveform check differs from spec",
        )
        require(check["status"] in ("passed", "failed", "invalid_evidence"), "invalid check status")
        if check["status"] == "invalid_evidence":
            same(
                (check["ok"], check["metrics"], check["assertions"]),
                (False, None, []),
                "invalid evidence upgraded",
            )
            require(
                check["reason"]
                in ("channel_not_captured", "window_exceeds_capture", "requires_dc_coupling"),
                "unknown invalid evidence reason",
            )
        else:
            require(bool(check["expect"]), "empty waveform assertions")
            integer(check["channel"], "channel", 1, 2 if report["source_kind"] == "ad3" else 4)
            window = check["window"]
            integer(window["start"], "sample start", 0, 16383)
            integer(window["end_exclusive"], "sample end", window["start"] + 1, 16384)
            samples = check["source_samples"]
            require(samples["coupling"] == "DC", "unsupported voltage coupling")
            if report["source_kind"] == "ad3":
                payload = base64.b64decode(capture["payload"]["raw_base64"], validate=True)
                same(
                    samples["raw"],
                    dict(
                        sha256=digest(payload),
                        size_bytes=len(payload),
                        encoding="f64le_channel_major",
                    ),
                    "AD3 sample binding differs",
                )
                stride, start = (
                    8,
                    capture["plan"]["channels"].index(check["channel"])
                    * capture["plan"]["samples"]
                    * 8,
                )
            else:
                stride, start = 2, 0
                for role, suffix in (("raw", "words.bin"), ("preamble", "preamble.bin")):
                    name = f"c{check['channel']}-{suffix}"
                    same(samples[role]["name"], name, "SDS channel file differs")
                    same(
                        {k: samples[role][k] for k in ("sha256", "size_bytes")},
                        {k: source_blobs[name][k] for k in ("sha256", "size_bytes")},
                        "SDS sample binding differs",
                    )
            same(
                (samples["stride"], samples["offset"]),
                (stride, start),
                "sample byte layout differs",
            )
            same(
                check["raw_span"],
                dict(
                    start=start + stride * window["start"],
                    end_exclusive=start + stride * window["end_exclusive"],
                ),
                "sample byte span differs",
            )
            require(
                check["raw_span"]["end_exclusive"] <= samples["raw"]["size_bytes"],
                "sample span exceeds retained bytes",
            )
            assertions = []
            for metric, limits in sorted(check["expect"].items()):
                value = check["metrics"][metric]
                require(type(value) in (int, float) and math.isfinite(value), "invalid metric")
                assertions.append(
                    dict(
                        metric=metric,
                        expected=limits,
                        actual=value,
                        ok=limits["minimum"] <= value <= limits["maximum"],
                    )
                )
            same(check["assertions"], assertions, "waveform assertion/metric contradiction")
            passed = all(a["ok"] for a in assertions)
            same(
                (check["ok"], check["status"]),
                (passed, "passed" if passed else "failed"),
                "native assertion verdict differs",
            )
    summary = dict(
        checks=len(checks),
        **{
            s: sum(c["status"] == s for c in checks)
            for s in ("passed", "failed", "invalid_evidence")
        },
    )
    same(report["summary"], summary, "native waveform summary differs")
    passed = summary["passed"] == len(checks)
    same(
        (report["ok"], report["status"]),
        (passed, "passed" if passed else "failed"),
        "native verdict differs",
    )
    for key in ("ok", "status", "summary", "checks", "source", "source_kind"):
        same(bundle[key], report[key], "HIL/native waveform projection differs")
    same(
        (bundle["native_exit_code"], manifest["native_exit_code"]),
        (0, 0) if passed else (3, 3),
        "native exit code differs",
    )
    require(native["schema_version"] == "lab-instruments.result.v1", "unsupported native response")
    for key in (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "outputs_commanded",
    ):
        require(native[key] is False, "native CLI claims upgraded")
    same(native["ok"], report["ok"], "native CLI verdict differs")
    verified = native["data"]["verification"]
    verifier_version = verified.get("verifier_version")
    require(
        verifier_version == "0.11.0"
        or verifier_version == "0.10.0"
        and report["runner_version"] in ("0.9.0", "0.10.0")
        or verifier_version == "0.9.0"
        and report["runner_version"] == "0.9.0",
        "unsupported native waveform producer/verifier pair",
    )
    bindings = {}
    for role in ("spec", "capture"):
        supplied = verified["bindings"][role]["supplied"]
        bound(supplied, bundle["inputs"][role])
        bindings[role] = dict(
            recorded=report[role],
            supplied=supplied,
            path_label_differs=report[role]["path"] != supplied["path"],
        )
    bound(verified["report"], bundle["inputs"]["report"])
    same(
        verified,
        {
            "schema_version": "lab-instruments.waveform-check-verification.v1",
            "ok": True,
            "status": "verified",
            "report": verified["report"],
            "bindings": bindings,
            "producer_runner_version": report["runner_version"],
            "verifier_version": verifier_version,
            "verdict": {k: report[k] for k in ("ok", "status", "summary")},
            "scope": "host_only_saved_waveform_verification",
            **NATIVE_FLAGS,
        },
        "native waveform verification differs",
    )
    counts = dict(
        tests=len(checks), failures=summary["failed"], errors=summary["invalid_evidence"], skipped=0
    )
    same(bundle["junit"], counts, "HIL JUnit summary differs")
    same(native["data"]["junit"], counts, "native JUnit summary differs")
    bound(native["data"]["output"], bundle["inputs"]["junit"])
    return bundle, ref


def view(path, sha, *, check=None, channel=None, status=None, offset=0, limit=8):
    integer(offset, "offset", 0, 8)
    integer(limit, "limit", 1, 8)
    if channel is not None:
        integer(channel, "channel", 1, 4)
    require(status in (None, "passed", "failed", "invalid_evidence"), "invalid waveform status")
    require(
        check is None or type(check) is str and len(check) <= 64, "invalid waveform check filter"
    )
    bundle, ref = load(path, sha)
    checks = [
        c
        for c in bundle["checks"]
        if (check is None or c["id"] == check)
        and (channel is None or c["channel"] == channel)
        and (status is None or c["status"] == status)
    ]
    return {
        "input": ref,
        "viewer_version": __version__,
        "source_kind": bundle["source_kind"],
        "source": bundle["source"],
        "verdict": {k: bundle[k] for k in ("ok", "status", "summary")},
        "junit": bundle["junit"],
        "native_exit_code": bundle["native_exit_code"],
        "native_recomputation_recorded": True,
        "hil_import_checks_reperformed": False,
        "source_files_rechecked": False,
        "clock_alignment_verified": False,
        "time_semantics": "sample_relative_no_verified_utc_origin",
        "matched_checks": len(checks),
        "selected_checks": len(checks[offset : offset + limit]),
        "checks": checks[offset : offset + limit],
        **FLAGS,
    }


def markdown(path, sha, output, **filters):
    # Validate the destination before loading the complete artifact.
    from .common import checked_path

    checked_path(output.parent)
    require(not output.exists() and not output.is_symlink(), "output already exists")
    value = view(path, sha, **filters)
    text = (
        "# Saved waveform checks\n\nGlobal verdict: "
        + value["verdict"]["status"]
        + "\n\nNative voltage recomputation and canonical JUnit validation are recorded, "
        "not repeated by this view. Timing, calibration, clipping, bandwidth and DUT identity "
        "remain unverified. Full evidence is retained in the hash-bound bundle.\n\n"
    )
    details = {**{k: value[k] for k in ("source_kind", "source", "verdict", "junit")}, **FLAGS}
    text += (
        "\n".join(
            "    " + line for line in json.dumps(details, ensure_ascii=True, indent=2).splitlines()
        )
        + "\n"
    )
    for check in value["checks"]:
        preview = json.dumps(check, ensure_ascii=True, sort_keys=True, indent=2)
        if len(preview) > 8192:
            preview = preview[:8192] + "\n[preview truncated; consult the bundle]"
        text += "\n" + "\n".join("    " + line for line in preview.splitlines()) + "\n"
    encoded = text.encode("ascii")
    require(len(encoded) <= 1048576, "waveform Markdown exceeds 1 MiB", "LIMIT_EXCEEDED")
    write_new_bytes(output, encoded)
    return {
        **value,
        "output": {"path": str(output), "sha256": digest(encoded), "size_bytes": len(encoded)},
    }
