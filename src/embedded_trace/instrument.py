"""File-only views of HIL's self-contained recorded instrument evidence."""

from __future__ import annotations

import base64
import json

from . import __version__
from .common import SHA, digest, integer, parse_json, read_file, require, write_new_bytes
from .report import _block

MAX_BUNDLE = 8 * 1024 * 1024
LIMITS = {
    "report": 1048576,
    "spec": 65536,
    "capture": 1048576,
    "native_result": 131072,
    "junit": 1048576,
}
FLAGS = {
    key: False
    for key in (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "physical_timing_verified",
        "calibration_verified",
        "endpoint_identity_verified",
        "report_authenticated",
        "native_recomputed_now",
        "source_execution_performed",
    )
}
NATIVE_FLAGS = {
    key: False
    for key in (
        "hardware_access",
        "executables_started",
        "authorization_granted",
        "physical_device_verified",
        "physical_timing_verified",
        "calibration_verified",
        "protocol_timing_compliance_verified",
        "endpoint_identity_verified",
    )
}
VERIFIER_PRODUCERS = {
    "0.8.0": ("0.7.0", "0.8.0"),
    "0.9.0": ("0.7.0", "0.8.0", "0.9.0"),
    "0.10.0": ("0.7.0", "0.8.0", "0.9.0", "0.10.0"),
    "0.11.0": ("0.7.0", "0.8.0", "0.9.0", "0.10.0", "0.11.0"),
}


def canonical(value):
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    require(len(raw) <= MAX_BUNDLE, "instrument view exceeds 8 MiB", "LIMIT_EXCEEDED")
    return raw


def same(left, right, message):
    require(canonical(left) == canonical(right), message, "EVIDENCE_MISMATCH")


def unpack(blob, maximum):
    require(
        isinstance(blob, dict) and set(blob) == {"path", "sha256", "size_bytes", "raw_base64"},
        "invalid embedded input",
    )
    require(
        type(blob["path"]) is str and 0 < len(blob["path"]) <= 4096, "invalid recorded path label"
    )
    size = integer(blob["size_bytes"], "snapshot bytes", 1, maximum)
    value = blob["raw_base64"]
    require(type(value) is str and len(value) == 4 * ((size + 2) // 3), "invalid base64 size")
    require(
        type(blob["sha256"]) is str and SHA.fullmatch(blob["sha256"]), "invalid snapshot SHA-256"
    )
    raw = base64.b64decode(value, validate=True)
    require(
        len(raw) == size
        and digest(raw) == blob["sha256"]
        and base64.b64encode(raw).decode() == value,
        "embedded input hash differs",
        "EVIDENCE_MISMATCH",
    )
    return raw


def bound(ref, blob):
    require(
        isinstance(ref, dict)
        and set(ref) == {"path", "sha256", "size_bytes"}
        and type(ref["path"]) is str,
        "invalid native reference",
    )
    same(
        {k: ref[k] for k in ("sha256", "size_bytes")},
        {k: blob[k] for k in ("sha256", "size_bytes")},
        "native input binding differs",
    )


def load(path, sha):
    raw, reference = read_file(path, MAX_BUNDLE, sha)
    bundle = parse_json(raw)
    require(
        set(bundle)
        == {
            "schema_version",
            "producer_version",
            "scope",
            *FLAGS,
            "ok",
            "status",
            "summary",
            "checks",
            "evidence_origin",
            "native_exit_code",
            "native_recomputation_recorded",
            "validation_kind",
            "junit",
            "import_spec",
            "inputs",
        },
        "invalid instrument bundle fields",
    )
    require(
        bundle["schema_version"] == "embedded-hil-runner.instrument-report.v1"
        and bundle["producer_version"]
        in ("0.9.0", "0.10.0", "0.11.0", "0.12.0", "0.13.0", "0.14.0", "0.15.0")
        and bundle["scope"] == "host_only_saved_instrument_import"
        and bundle["native_recomputation_recorded"] is True
        and bundle["validation_kind"] == "recorded_native_verification_and_explicit_input_integrity"
        and all(bundle[k] is False for k in FLAGS),
        "invalid HIL instrument qualification",
    )
    inputs = bundle["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == set(LIMITS), "invalid embedded input roles")
    decoded = {role: unpack(inputs[role], maximum) for role, maximum in LIMITS.items()}
    spec = parse_json(unpack(bundle["import_spec"], 16384))
    require(
        set(spec) == {"schema_version", "native_exit_code", "inputs"}
        and spec["schema_version"] == "embedded-hil-runner.instrument-spec.v1"
        and isinstance(spec["inputs"], dict)
        and set(spec["inputs"]) == set(LIMITS),
        "invalid recorded import spec",
    )
    for role, item in spec["inputs"].items():
        require(
            isinstance(item, dict)
            and set(item) == {"path", "sha256"}
            and type(item["path"]) is str,
            "invalid recorded import binding",
        )
        same(item["sha256"], inputs[role]["sha256"], "import binding differs")
    report, contract, capture, response = (
        parse_json(decoded[role]) for role in ("report", "spec", "capture", "native_result")
    )
    require(
        report.get("schema_version") == "lab-instruments.logic-check-report.v1"
        and report.get("runner_version") in ("0.7.0", "0.8.0", "0.9.0", "0.10.0", "0.11.0")
        and report.get("scope") == "host_only_saved_logic_evaluation"
        and report.get("complete") is True
        and all(report.get(k) is False for k in NATIVE_FLAGS),
        "invalid recorded native report",
    )
    require(
        contract.get("schema_version") == "lab-instruments.logic-check-spec.v1"
        and isinstance(contract.get("checks"), list),
        "invalid recorded assertion spec",
    )
    require(
        capture.get("schema_version") == "lab-instruments.capture.v1"
        and capture.get("instrument") == "logic"
        and type(capture.get("ok")) is bool
        and capture.get("evidence_origin") in ("test_double", "physical_instrument"),
        "invalid saved capture",
    )
    for role in ("spec", "capture"):
        bound(report[role], inputs[role])
    checks = report["checks"]
    require(
        type(checks) is list and 1 <= len(checks) <= 8 and len(checks) == len(contract["checks"]),
        "invalid check count",
    )
    seen = set()
    for check, expected in zip(checks, contract["checks"], strict=True):
        require(
            isinstance(expected, dict)
            and set(expected) == {"id", "kind", "configuration", "expect"},
            "invalid native check spec",
        )
        same({k: check[k] for k in expected}, expected, "check differs from original spec")
        require(
            type(check["id"]) is str
            and check["id"] not in seen
            and check["kind"] in ("uart", "pwm", "i2c", "spi"),
            "invalid check identity",
        )
        seen.add(check["id"])
        native = check["native"]
        require(
            digest(canonical(native)) == check["native_sha256"],
            "native hash differs",
            "EVIDENCE_MISMATCH",
        )
        same(native["capture"], report["capture"], "native capture binding differs")
        for key, value in {
            "source_ok": capture["ok"],
            "source_status": capture["status"],
            "source_error": capture.get("error"),
            "source_cleanup": capture["cleanup"],
            "evidence_origin": capture["evidence_origin"],
        }.items():
            same(native[key], value, "native source declaration differs")
        require(
            type(native.get("ok")) is bool
            and (capture["ok"] or native["ok"] is False)
            and all(
                native.get(k) is False
                for k in (
                    "hardware_access",
                    "executables_started",
                    "physical_timing_verified",
                    "calibration_verified",
                )
            ),
            "native source/physical claim invalid",
        )
        assertions = check["assertions"]
        require(
            type(assertions) is list
            and 1 <= len(assertions) <= 16
            and all(
                isinstance(a, dict) and a.get("status") in ("passed", "failed", "not_evaluated")
                for a in assertions
            ),
            "invalid native assertions",
        )
        passed = all(a["status"] == "passed" for a in assertions)
        same(check["ok"], passed, "native check verdict differs")
        same(
            check["status"],
            "passed" if passed else ("failed" if native["ok"] else "invalid_evidence"),
            "native check status differs",
        )
        require(not passed or native["ok"], "invalid evidence upgraded")
    expected_summary = {
        "checks": len(checks),
        "passed": sum(c["ok"] for c in checks),
        "failed": sum(not c["ok"] for c in checks),
    }
    same(report["summary"], expected_summary, "native summary differs")
    same(report["ok"], all(c["ok"] for c in checks), "native verdict differs")
    same(report["status"], "passed" if report["ok"] else "failed", "native status differs")
    for key in ("ok", "status", "summary", "evidence_origin"):
        same(bundle[key], report[key], "HIL summary differs from native report")
    same(report["evidence_origin"], capture["evidence_origin"], "source origin differs")
    same(
        bundle["checks"],
        [{k: c[k] for k in ("id", "kind", "status", "native_sha256")} for c in checks],
        "HIL checks differ",
    )
    counts = {
        "tests": len(checks),
        "failures": sum(c["status"] == "failed" for c in checks),
        "errors": sum(c["status"] == "invalid_evidence" for c in checks),
        "skipped": 0,
    }
    require(
        response.get("schema_version") == "lab-instruments.result.v1"
        and all(
            response.get(k) is False
            for k in (
                "hardware_access",
                "executables_started",
                "authorization_granted",
                "physical_device_verified",
                "outputs_commanded",
            )
        ),
        "invalid native CLI result",
    )
    same(response["ok"], report["ok"], "CLI verdict differs")
    verified = response["data"]["verification"]
    require(
        verified.get("schema_version") == "lab-instruments.logic-check-verification.v1"
        and type(verified.get("verifier_version")) is str
        and report["runner_version"] in VERIFIER_PRODUCERS.get(verified["verifier_version"], ())
        and verified.get("ok") is True
        and verified.get("status") == "verified"
        and verified.get("complete") is True
        and verified.get("scope") == "host_only_saved_logic_verification"
        and all(
            verified.get(k) is False
            for k in (*NATIVE_FLAGS, "report_authenticated", "recorded_paths_followed")
        ),
        "invalid recorded native verification",
    )
    same(verified["producer_runner_version"], report["runner_version"], "producer differs")
    same(
        verified["verdict"],
        {k: report[k] for k in ("ok", "status", "summary")},
        "recorded verification verdict differs",
    )
    same(
        verified["checks"],
        [{k: c[k] for k in ("id", "kind", "status")} for c in checks],
        "recorded verification checks differ",
    )
    same(verified["evidence_origin"], report["evidence_origin"], "verification source differs")
    bound(verified["report"], inputs["report"])
    for role in ("spec", "capture"):
        same(verified[role + "_binding"]["recorded"], report[role], "recorded binding differs")
        bound(verified[role + "_binding"]["supplied"], inputs[role])
    bound(response["data"]["output"], inputs["junit"])
    same(bundle["junit"], counts, "HIL JUnit counts differ")
    same(response["data"]["junit"], counts, "native JUnit counts differ")
    for code in (bundle["native_exit_code"], spec["native_exit_code"]):
        same(code, 0 if report["ok"] else 3, "native exit code differs")
    return bundle, report, reference


def view(path, sha, *, check=None, kind=None, status=None, offset=0, limit=8):
    integer(offset, "offset", 0, 8)
    integer(limit, "limit", 1, 8)
    require(kind is None or kind in ("uart", "pwm", "i2c", "spi"), "invalid kind filter")
    require(
        status is None or status in ("passed", "failed", "invalid_evidence"),
        "invalid status filter",
    )
    bundle, report, ref = load(path, sha)
    require(check is None or check in [c["id"] for c in report["checks"]], "unknown check ID")
    matches = [
        c
        for c in report["checks"]
        if (check is None or c["id"] == check)
        and (kind is None or c["kind"] == kind)
        and (status is None or c["status"] == status)
    ]
    return {
        "input": ref,
        "viewer_version": __version__,
        "verdict": {k: bundle[k] for k in ("ok", "status", "summary")},
        "evidence_origin": bundle["evidence_origin"],
        "native_recomputation_recorded": True,
        "hil_import_checks_reperformed": False,
        "source_files_rechecked": False,
        "clock_alignment_verified": False,
        "time_semantics": "sample_relative_no_verified_utc_origin",
        "junit": bundle["junit"],
        "input_hashes": {role: blob["sha256"] for role, blob in bundle["inputs"].items()},
        "matched_count": len(matches),
        "selected_count": len(matches[offset : offset + limit]),
        "checks": matches[offset : offset + limit],
        **FLAGS,
    }


def markdown(path, sha, output, **filters):
    # Output preflight before loading the potentially large saved evidence.
    from .common import checked_path, relative_source

    parent = checked_path(output.parent)
    target = relative_source(parent, output.name)
    require(not target.exists() and not target.is_symlink(), "output exists", "OUTPUT_EXISTS")
    value = view(path, sha, **filters)
    blocks = ["# Instrument checks\n\n", _block({k: v for k, v in value.items() if k != "checks"})]
    for check in value["checks"]:
        detail = {k: check[k] for k in ("id", "kind", "status", "native_sha256", "assertions")}
        native = check["native"]
        detail.update(
            {
                k: native[k]
                for k in (
                    "source_status",
                    "source_error",
                    "source_cleanup",
                    "time_domain",
                    "raw_span_unit",
                )
            }
        )
        preview = canonical(native).decode("ascii")
        detail.update(native_json_preview=preview[:2048], native_json_truncated=len(preview) > 2048)
        blocks.append(_block(detail))
    ref = write_new_bytes(target, "".join(blocks).encode("utf-8"), maximum=1048576)
    return {k: v for k, v in value.items() if k != "checks"} | {
        "output": ref,
        "preview_is_test_verdict": False,
    }
