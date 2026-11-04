"""Independent PPI raw fixtures validate representation without replaying native policy."""

import base64
import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.ppi import PPI_FIELDS, PPI_LABELS, PPI_PROFILE
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.timeline import correlate


def ppi_report(root, fault="none", unknown=False, lifecycle=False):
    # Only one sample and sentinel=1: Trace preserves declarations, not firmware policy.
    uart = b"READY\r\nBUILD abc\r\nSAMPLE 00000001 A=00000001 B=00000000 S=00000001\r\n"
    path = evidence(root, qemu=False, passed=fault == "none" and not unknown, uart=uart)
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    stdout, observations = b"", []
    names = (
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
    values = (
        1,
        4,
        1000,
        1,
        1073774912,
        1073766400,
        1073766404,
        199427,
        205571,
        199939,
        2048,
        8,
        2048,
        8,
    )
    for index in range(8):
        if index == 4 and fault != "none":
            stdout += b"SIM_PPI_FAULT\r\n"
        for phase in ("PRE", "POST"):
            raw = f"SIM_PPI_OBS_{index}_{phase}\r\n".encode()
            for value in values:
                if lifecycle:
                    raw += b"[11:11:35.4640] [INFO] nrf52840-ppi: Machine paused.\r\n" * (
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
        samples=[dict(sequence=1, a=1, b=0, sentinel=1)],
        model_observations=observations,
        fault_scenario=fault,
        **PPI_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.ppi-report.v1",
        profile=PPI_PROFILE,
        fault_scenario=fault,
        **PPI_LABELS,
        assertions=None if unknown else assertions,
        errors=[]
        if passed
        else [dict(code="TIMEOUT" if unknown else "ASSERTION_FAILED", message="recorded failure")],
        virtual_time=dict(domain="renode_emulation", requested_ms=40, completed=not unknown),
    )
    plan.update(
        schema_version="embedded-sim-runner.ppi-plan.v1",
        runner_version="0.14.0",
        profile=PPI_PROFILE,
        backend="renode",
        virtual_ms=40,
        fault_scenario=fault,
        **PPI_LABELS,
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


@pytest.mark.parametrize("fault", ("none", "ppi-fork-misroute", "ppi-channel-disable"))
@pytest.mark.parametrize("unknown", (False, True))
def test_ppi_full_filtered_empty_and_moved_views(tmp_path, monkeypatch, fault, unknown):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("offline spawned"))
    path = ppi_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["ppi_evidence"] == native["assertions"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert len(source["ppi_sample_spans"]) == (0 if unknown else 1)
    assert len(source["ppi_observation_spans"]) == (0 if unknown else 16)
    assert (source["ppi_fault_span"] is not None) == (fault != "none" and not unknown)
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
        assert all(summary[k] == source[k] for k in PPI_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    out = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), out, contains="NO_SUCH_LINE")
    assert all(k in out.read_text() for k in PPI_FIELDS)


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
def test_ppi_rehashed_contradictions_are_rejected(tmp_path, mutation):
    path = ppi_report(tmp_path / "native", "ppi-fork-misroute")
    doc = correlate(spec(path))
    s = doc["sources"][0]
    ev = s["ppi_evidence"]
    if mutation == "coverage":
        s["physical_timing_verified"] = True
    if mutation == "effect":
        ev["fault"]["effect_observed"] = False
    if mutation == "clock":
        s["virtual_time"]["requested_ms"] = 41
    if mutation == "sample":
        ev["samples"][0]["a"] ^= 1
    if mutation == "sample-span":
        s["ppi_sample_spans"][0]["byte_start"] += 1
    if mutation == "model-span":
        v = s["ppi_observation_spans"][0]
        raw = base64.b64decode(v["raw_base64"]).replace(b"1073766404", b"1073766408")
        v.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "fault-span":
        s["ppi_fault_span"]["byte_start"] = 0
    if mutation == "missing":
        s.pop("ppi_fault_span")
    if mutation == "bool-int":
        ev["samples"][0]["sequence"] = True
    if mutation == "overflow":
        ev["model_observations"][0]["registers"]["timer_event"] = 2**32
    if mutation == "count":
        s["ppi_sample_spans"] *= 2
    if mutation == "request":
        s["fault_request"]["stimulus_index"] = 5
    if mutation == "span-type":
        s["ppi_sample_spans"][0] = 123
    if mutation == "row-type":
        ev["model_observations"][0] = 123
    with pytest.raises(TraceError):
        validate(doc)


def test_ppi_import_rejects_rehashed_model_bytes(tmp_path):
    path = ppi_report(tmp_path / "native", "ppi-fork-misroute")
    native = json.loads(path.read_bytes())
    raw = (path.parent / "backend.stdout.bin").read_bytes().replace(b"1073766404", b"1073766408", 1)
    (path.parent / "backend.stdout.bin").write_bytes(raw)
    native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))


@pytest.mark.parametrize("lifecycle", [True, "dense"])
def test_ppi_preserves_interleaved_lifecycle_info_without_rejudging_values(tmp_path, lifecycle):
    path = ppi_report(tmp_path / "native", lifecycle=lifecycle)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    # These saved declarations intentionally contain sentinel=1 and only one
    # sample. Trace preserves native policy claims; it only verifies raw bindings.
    assert source["ppi_evidence"]["samples"][0]["sentinel"] == 1
    assert source["capture_outcome"] == "succeeded"
    raw = base64.b64decode(source["ppi_observation_spans"][0]["raw_base64"])
    assert b"Machine paused." in raw
    if lifecycle == "dense":
        assert len(raw) > 256


@pytest.mark.parametrize(
    "key,value",
    [
        ("timer_event", True),
        ("timer_event", 2),
        ("channel_mask", -1),
        ("fork_endpoint", 2**32),
        ("gpio1_out", False),
        ("timer_prescaler", "4"),
    ],
)
def test_ppi_invalid_model_register_representation_rejected(tmp_path, key, value):
    path = ppi_report(tmp_path / "native")
    doc = correlate(spec(path))
    doc["sources"][0]["ppi_evidence"]["model_observations"][0]["registers"][key] = value
    with pytest.raises(TraceError):
        validate(doc)


def test_ppi_missing_register_rejected(tmp_path):
    path = ppi_report(tmp_path / "native")
    doc = correlate(spec(path))
    del doc["sources"][0]["ppi_evidence"]["model_observations"][0]["registers"]["fork_endpoint"]
    with pytest.raises(TraceError):
        validate(doc)


def test_ppi_failed_identity_preserves_model_without_guest_or_fault_claim(tmp_path):
    path = ppi_report(tmp_path / "native", "ppi-fork-misroute")
    native = json.loads(path.read_bytes())
    native["assertions"].update(
        samples=[],
        nominal_failure="PPI READY/BUILD differs",
        fault=dict(id="ppi-fork-misroute", effect_observed=None, status="not_evaluated"),
    )
    path.write_text(json.dumps(native))
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["capture_outcome"] == "failed"
    assert len(source["ppi_observation_spans"]) == 16
    assert source["ppi_sample_spans"] == []
    assert source["ppi_evidence"]["fault"]["effect_observed"] is None
