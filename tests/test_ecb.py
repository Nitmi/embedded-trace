"""Independent ECB raw fixtures validate representation without replaying native policy."""

import base64
import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.ecb import ECB_FIELDS, ECB_LABELS, ECB_PROFILE
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.timeline import correlate


def ecb_report(root, fault="none", unknown=False, lifecycle=False):
    # One sample and unusual word/guard values: preserve native declarations,
    # without replaying firmware policy.
    uart = (
        b"READY\r\nBUILD abc\r\nSAMPLE 00000001 OUT=0123456789ABCDEF0123456789ABCDEF END=00000003 "
        b"LO=13579BDF HI=2468ACE1\r\n"
    )
    path = evidence(root, qemu=False, passed=fault == "none" and not unknown, uart=uart)
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    stdout, observations = b"", []
    # Literal independent inventory, not imported from the implementation under test.
    names = (
        "data_pointer",
        "end",
        "interrupt_mask",
        "mailbox",
        "guard_low",
        "key0",
        "key1",
        "key2",
        "key3",
        "plaintext0",
        "plaintext1",
        "plaintext2",
        "plaintext3",
        "ciphertext0",
        "ciphertext1",
        "ciphertext2",
        "ciphertext3",
        "guard_high",
        "alternate_guard_low",
        "alternate_key0",
        "alternate_key1",
        "alternate_key2",
        "alternate_key3",
        "alternate_plaintext0",
        "alternate_plaintext1",
        "alternate_plaintext2",
        "alternate_plaintext3",
        "alternate_ciphertext0",
        "alternate_ciphertext1",
        "alternate_ciphertext2",
        "alternate_ciphertext3",
        "alternate_guard_high",
    )
    values = (536875012, 1, 0, 0) + tuple(range(28))
    for index in range(8):
        if index == 4 and fault != "none":
            stdout += b"SIM_ECB_FAULT\r\n"
        for phase in ("PRE", "POST"):
            raw = f"SIM_ECB_OBS_{index}_{phase}\r\n".encode()
            for value in values:
                if lifecycle:
                    raw += b"[11:11:35.4640] [INFO] nrf52840-ecb: Machine paused.\r\n" * (
                        4 if lifecycle == "dense" else 1
                    )
                raw += f"{value}\r\n".encode()
            observations.append(
                dict(
                    index=index,
                    phase=phase,
                    registers=dict(zip(names, values, strict=True)),
                    stdout_offset=len(stdout),
                    stdout_bytes=len(raw),
                    stdout_sha256=digest(raw),
                )
            )
            stdout += raw
    passed = fault == "none" and not unknown
    assertions = dict(
        nominal_regression_passed=passed,
        nominal_failure=None if passed else "recorded failure",
        fault=dict(
            id=fault,
            effect_observed=None if fault == "none" else True,
            status="not_evaluated" if fault == "none" else "observed",
        ),
        samples=[
            dict(
                sequence=1,
                ciphertext="0123456789abcdef0123456789abcdef",
                end=3,
                guard_low=0x13579BDF,
                guard_high=0x2468ACE1,
            )
        ],
        model_observations=observations,
        fault_scenario=fault,
        **ECB_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.ecb-report.v1",
        profile=ECB_PROFILE,
        fault_scenario=fault,
        **ECB_LABELS,
        assertions=None if unknown else assertions,
        errors=[]
        if passed
        else [dict(code="TIMEOUT" if unknown else "ASSERTION_FAILED", message="recorded failure")],
        virtual_time=dict(domain="renode_emulation", requested_ms=40, completed=not unknown),
    )
    plan.update(
        schema_version="embedded-sim-runner.ecb-plan.v1",
        runner_version="0.16.0",
        profile=ECB_PROFILE,
        backend="renode",
        virtual_ms=40,
        fault_scenario=fault,
        **ECB_LABELS,
        scenario=dict(fault=dict(id=fault, stimulus_index=None if fault == "none" else 4)),
        assertions=dict(heartbeat_prefix="SAMPLE"),
        script_sha256=digest((root / "run.resc").read_bytes()),
    )
    (root / "plan.json").write_text(json.dumps(plan))
    (root / "backend.stdout.bin").write_bytes(b"" if unknown else stdout)
    for name in ("plan.json", "backend.stdout.bin"):
        raw = (root / name).read_bytes()
        native["artifacts"][name].update(sha256=digest(raw), bytes=len(raw))
    native["plan_sha256"] = digest((root / "plan.json").read_bytes())
    path.write_text(json.dumps(native))
    return path


@pytest.mark.parametrize("fault", ("none", "context-redirect", "plaintext-stuck"))
@pytest.mark.parametrize("unknown", (False, True))
def test_ecb_full_filtered_empty_and_moved_views(tmp_path, monkeypatch, fault, unknown):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("offline spawned"))
    path = ecb_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["ecb_evidence"] == native["assertions"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert len(source["ecb_sample_spans"]) == (0 if unknown else 1)
    assert len(source["ecb_observation_spans"]) == (0 if unknown else 16)
    assert (source["ecb_fault_span"] is not None) == (fault != "none" and not unknown)
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    path.rename(path.with_suffix(".moved"))
    (path.parent / "backend.stdout.bin").rename(path.parent / "stdout.moved")
    for result in (
        inspect(timeline, digest(timeline.read_bytes())),
        query(timeline, digest(timeline.read_bytes()), contains="SAMPLE"),
        query(timeline, digest(timeline.read_bytes()), contains="NO_SUCH_LINE"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert all(summary[k] == source[k] for k in ECB_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    out = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), out, contains="NO_SUCH_LINE")
    assert all(k in out.read_text() for k in ECB_FIELDS)


@pytest.mark.parametrize(
    "mutation",
    (
        "coverage",
        "effect",
        "clock",
        "sample",
        "sample-span",
        "model-span",
        "fault-span",
        "missing",
        "bool-int",
        "overflow",
        "count",
        "request",
        "span-type",
        "row-type",
    ),
)
def test_ecb_rehashed_contradictions_are_rejected(tmp_path, mutation):
    path = ecb_report(tmp_path / "native", "context-redirect")
    doc = correlate(spec(path))
    s = doc["sources"][0]
    ev = s["ecb_evidence"]
    if mutation == "coverage":
        s["physical_timing_verified"] = True
    if mutation == "effect":
        ev["fault"]["effect_observed"] = False
    if mutation == "clock":
        s["virtual_time"]["requested_ms"] = 41
    if mutation == "sample":
        ev["samples"][0]["ciphertext"] = "f" * 32
    if mutation == "sample-span":
        s["ecb_sample_spans"][0]["byte_start"] += 1
    if mutation == "model-span":
        v = s["ecb_observation_spans"][0]
        raw = base64.b64decode(v["raw_base64"]).replace(b"536875012", b"536875016")
        v.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "fault-span":
        s["ecb_fault_span"]["byte_start"] = 0
    if mutation == "missing":
        s.pop("ecb_fault_span")
    if mutation == "bool-int":
        ev["samples"][0]["sequence"] = True
    if mutation == "overflow":
        ev["model_observations"][0]["registers"]["end"] = 2**32
    if mutation == "count":
        s["ecb_sample_spans"] *= 2
    if mutation == "request":
        s["fault_request"]["stimulus_index"] = 5
    if mutation == "span-type":
        s["ecb_sample_spans"][0] = 123
    if mutation == "row-type":
        ev["model_observations"][0] = 123
    with pytest.raises(TraceError):
        validate(doc)


def test_ecb_import_rejects_rehashed_model_bytes(tmp_path):
    path = ecb_report(tmp_path / "native", "context-redirect")
    native = json.loads(path.read_bytes())
    raw = (path.parent / "backend.stdout.bin").read_bytes().replace(b"536875012", b"536875016", 1)
    (path.parent / "backend.stdout.bin").write_bytes(raw)
    native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))


@pytest.mark.parametrize("lifecycle", [True, "dense"])
def test_ecb_preserves_interleaved_lifecycle_info_without_rejudging_values(tmp_path, lifecycle):
    path = ecb_report(tmp_path / "native", lifecycle=lifecycle)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    # These saved declarations intentionally contain unusual word/guard values and only one
    # sample. Trace preserves native policy claims; it only verifies raw bindings.
    assert source["ecb_evidence"]["samples"][0]["guard_high"] == 0x2468ACE1
    assert source["capture_outcome"] == "succeeded"
    raw = base64.b64decode(source["ecb_observation_spans"][0]["raw_base64"])
    assert b"Machine paused." in raw
    if lifecycle == "dense":
        assert len(raw) > 4096


@pytest.mark.parametrize(
    "key,value",
    [
        ("end", True),
        ("end", 2**32),
        ("data_pointer", -1),
        ("ciphertext3", 2**32),
        ("guard_high", False),
        ("alternate_key3", "4"),
    ],
)
def test_ecb_invalid_model_register_representation_rejected(tmp_path, key, value):
    path = ecb_report(tmp_path / "native")
    doc = correlate(spec(path))
    doc["sources"][0]["ecb_evidence"]["model_observations"][0]["registers"][key] = value
    with pytest.raises(TraceError):
        validate(doc)


def test_ecb_missing_register_rejected(tmp_path):
    path = ecb_report(tmp_path / "native")
    doc = correlate(spec(path))
    del doc["sources"][0]["ecb_evidence"]["model_observations"][0]["registers"]["data_pointer"]
    with pytest.raises(TraceError):
        validate(doc)


def test_ecb_failed_identity_preserves_model_without_guest_or_fault_claim(tmp_path):
    path = ecb_report(tmp_path / "native", "context-redirect")
    native = json.loads(path.read_bytes())
    native["assertions"].update(
        samples=[],
        nominal_failure="ECB READY/BUILD differs",
        fault=dict(id="context-redirect", effect_observed=None, status="not_evaluated"),
    )
    path.write_text(json.dumps(native))
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["capture_outcome"] == "failed"
    assert len(source["ecb_observation_spans"]) == 16
    assert source["ecb_sample_spans"] == []
    assert source["ecb_evidence"]["fault"]["effect_observed"] is None


@pytest.mark.parametrize("version", ["0.15.0", "0.17.0", "99.0.0"])
def test_ecb_rejects_unselected_plan_versions(tmp_path, version):
    path = ecb_report(tmp_path / "native")
    native = json.loads(path.read_bytes())
    plan_path = path.parent / "plan.json"
    plan = json.loads(plan_path.read_bytes())
    plan["runner_version"] = version
    plan_path.write_text(json.dumps(plan))
    native["artifacts"]["plan.json"].update(
        sha256=digest(plan_path.read_bytes()), bytes=plan_path.stat().st_size
    )
    native["plan_sha256"] = digest(plan_path.read_bytes())
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))


@pytest.mark.parametrize("value", [True, 3, "A" * 32, "g" * 32, "f" * 31, "f" * 34])
def test_ecb_ciphertext_must_be_exact_lowercase_block(tmp_path, value):
    path = ecb_report(tmp_path / "native")
    doc = correlate(spec(path))
    doc["sources"][0]["ecb_evidence"]["samples"][0]["ciphertext"] = value
    with pytest.raises(TraceError):
        validate(doc)


@pytest.mark.parametrize(
    "field",
    [
        "crypto_hardware_verified",
        "cryptographic_security_qualified",
        "side_channel_resistance_verified",
    ],
)
def test_ecb_rejects_security_qualification_escalation(tmp_path, field):
    path = ecb_report(tmp_path / "native")
    doc = correlate(spec(path))
    doc["sources"][0][field] = True
    with pytest.raises(TraceError):
        validate(doc)
