"""Independent saved RTC byte fixtures: representation checks, no native policy."""

import base64
import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.rtc import RTC_FIELDS, RTC_LABELS, RTC_PROFILE
from embedded_trace.timeline import correlate


def rtc_report(root, fault="none", unknown=False):
    # Deliberately bad (but recorded) event_after=1 proves Trace does not rejudge firmware.
    uart = (
        b"READY\r\nBUILD abc\r\nSAMPLE 00000001 C=00000010 E=00000001"
        b" A=00000001 N=00000020 P=0000001F V=0000001B\r\n"
    )
    path = evidence(root, qemu=False, passed=fault == "none" and not unknown, uart=uart)
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    stdout, observations = b"", []
    for index in range(4):
        if index == 1 and fault != "none":
            stdout += b"SIM_RTC_FAULT\r\n"
        raw = f"SIM_RTC_OBS_{index}\r\n40\r\n31\r\n48\r\n0\r\n65536\r\n".encode()
        observations.append(
            dict(
                index=index,
                counter=40,
                prescaler=31,
                compare=48,
                event=0,
                interrupt_mask=65536,
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
                counter=16,
                event_before=1,
                event_after=1,
                next_compare=32,
                prescaler=31,
                irq_vector=27,
            )
        ],
        model_observations=observations,
        fault_scenario=fault,
        **RTC_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.rtc-report.v1",
        profile=RTC_PROFILE,
        fault_scenario=fault,
        **RTC_LABELS,
        assertions=None if unknown else assertions,
        errors=[]
        if passed
        else [dict(code="TIMEOUT" if unknown else "ASSERTION_FAILED", message="recorded failure")],
        virtual_time=dict(domain="renode_emulation", requested_ms=162, completed=not unknown),
    )
    plan.update(
        schema_version="embedded-sim-runner.rtc-plan.v1",
        runner_version="0.11.0",
        profile=RTC_PROFILE,
        backend="renode",
        virtual_ms=162,
        fault_scenario=fault,
        **RTC_LABELS,
        scenario=dict(fault=dict(id=fault, requested_virtual_ms=None if fault == "none" else 42)),
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


@pytest.mark.parametrize("fault", ("none", "rtc-stop", "rtc-irq-mask"))
@pytest.mark.parametrize("unknown", (False, True))
def test_rtc_full_filtered_empty_and_moved_views(tmp_path, monkeypatch, fault, unknown):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("offline spawned"))
    path = rtc_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["rtc_evidence"] == native["assertions"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert len(source["rtc_sample_spans"]) == (0 if unknown else 1)
    assert len(source["rtc_observation_spans"]) == (0 if unknown else 4)
    assert (source["rtc_fault_span"] is not None) == (fault != "none" and not unknown)
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
        assert all(summary[k] == source[k] for k in RTC_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    out = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), out, contains="NO_SUCH_LINE")
    assert all(k in out.read_text() for k in RTC_FIELDS)


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
def test_rtc_rehashed_contradictions_are_rejected(tmp_path, mutation):
    path = rtc_report(tmp_path / "native", "rtc-stop")
    doc = correlate(spec(path))
    s = doc["sources"][0]
    ev = s["rtc_evidence"]
    if mutation == "coverage":
        s["physical_timing_verified"] = True
    if mutation == "effect":
        ev["fault"]["effect_observed"] = False
    if mutation == "clock":
        s["virtual_time"]["requested_ms"] = 163
    if mutation == "sample":
        ev["samples"][0]["counter"] = 17
    if mutation == "sample-span":
        s["rtc_sample_spans"][0]["byte_start"] += 1
    if mutation == "model-span":
        v = s["rtc_observation_spans"][0]
        raw = base64.b64decode(v["raw_base64"]).replace(b"65536", b"65537")
        v.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "fault-span":
        s["rtc_fault_span"]["byte_start"] = 0
    if mutation == "missing":
        s.pop("rtc_fault_span")
    if mutation == "bool-int":
        ev["samples"][0]["sequence"] = True
    if mutation == "overflow":
        ev["model_observations"][0]["counter"] = 2**32
    if mutation == "count":
        s["rtc_sample_spans"] *= 2
    if mutation == "request":
        s["fault_request"]["requested_virtual_ms"] = 43
    if mutation == "span-type":
        s["rtc_sample_spans"][0] = 123
    if mutation == "row-type":
        ev["model_observations"][0] = 123
    with pytest.raises(TraceError):
        validate(doc)


def test_rtc_import_rejects_rehashed_model_bytes(tmp_path):
    path = rtc_report(tmp_path / "native", "rtc-stop")
    native = json.loads(path.read_bytes())
    raw = (path.parent / "backend.stdout.bin").read_bytes().replace(b"65536", b"65537", 1)
    (path.parent / "backend.stdout.bin").write_bytes(raw)
    native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))
