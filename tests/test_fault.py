"""Offline fault provenance; native regression policy is deliberately not rerun."""

import base64
import json

import pytest
from test_gpio import gpio_report
from test_simulation import spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import FAULT_FIELDS, FAULT_PROFILE, FAULT_SCOPE, FAULTS
from embedded_trace.timeline import correlate


def fault_report(root, fault="timer-stop", *, unknown=False, unobserved=False):
    path = gpio_report(root)
    report = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    coverage = {"fault_scenario": fault, "fault_scope": FAULT_SCOPE}
    plan.update(
        schema_version="embedded-sim-runner.gpio-fault-plan.v1", profile=FAULT_PROFILE, **coverage
    )
    plan["scenario"] = {
        "fault": {"id": fault, "requested_virtual_ms": None if fault == "none" else 22}
    }
    (root / "plan.json").write_text(json.dumps(plan))
    observations = report["assertions"]["model_observations"]
    stdout = b"[INFO] \xd1\xe9\xca\xd5/run.resc\r\n"
    for row in observations:
        row.update(timer_counter=5000, interrupt_enable=65536)
        values = [
            row[k] for k in ("out_register", "in_register", "timer_counter", "interrupt_enable")
        ]
        stdout += f"SIM_FAULT_OBS_{row['phase']}\r\n".encode()
        stdout += b"".join(f"{value}\r\n".encode() for value in values)
    (root / "backend.stdout.bin").write_bytes(stdout)
    passed = fault == "none" and not unknown
    assertions = {
        **report["assertions"],
        "nominal_regression_passed": passed,
        "nominal_failure": None if passed else "native nominal test failed",
        "fault": {
            "id": fault,
            "effect_observed": None if fault == "none" else not unobserved,
            "status": "not_requested"
            if fault == "none"
            else "not_observed"
            if unobserved
            else "observed",
        },
        "ready_matches": True,
        "build_matches": True,
    }
    report.update(
        schema_version="embedded-sim-runner.gpio-fault-report.v1",
        profile=FAULT_PROFILE,
        ok=passed,
        status="passed" if passed else "failed",
        assertions=None if unknown else assertions,
        errors=[]
        if passed
        else [
            {"code": "TIMEOUT" if unknown else "ASSERTION_FAILED", "message": "synthetic failure"}
        ],
        **coverage,
    )
    report["virtual_time"]["completed"] = not unknown
    for name in ("plan.json", "backend.stdout.bin"):
        raw = (root / name).read_bytes()
        report["artifacts"][name].update(sha256=digest(raw), bytes=len(raw))
    report["plan_sha256"] = digest((root / "plan.json").read_bytes())
    path.write_text(json.dumps(report))
    return path


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("unknown,unobserved", [(False, False), (True, False), (False, True)])
def test_fault_native_verdict_and_unknown_effect_survive_views(
    tmp_path, monkeypatch, fault, unknown, unobserved
):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline import spawned"))
    path = fault_report(tmp_path / "native", fault, unknown=unknown, unobserved=unobserved)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert source["fault_evidence"] == native["assertions"]
    assert source["native_errors"] == native["errors"]
    stdout = (path.parent / "backend.stdout.bin").read_bytes()
    for span in source["gpio_observation_spans"]:
        assert base64.b64decode(span["raw_base64"]) == stdout[span["byte_start"] : span["byte_end"]]
    if unknown:
        assert source["fault_evidence"] is None and source["gpio_observation_spans"] == []
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    path.rename(path.with_suffix(".moved"))
    (path.parent / "backend.stdout.bin").rename(path.parent / "stdout.moved")
    for result in (
        inspect(timeline, digest(timeline.read_bytes())),
        query(timeline, digest(timeline.read_bytes()), contains="HEARTBEAT"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert all(summary[key] == source[key] for key in FAULT_FIELDS)
        assert summary["recorded_status"] == native["status"]
    output = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), output)
    assert all(key in output.read_text() for key in FAULT_FIELDS)


@pytest.mark.parametrize(
    "mutation",
    ["effect", "nominal", "request", "error", "counter", "irq", "span", "newline", "coverage"],
)
def test_rehashed_fault_timeline_rejects_changed_summary_or_span(tmp_path, mutation):
    doc = correlate(spec(fault_report(tmp_path / "native")))
    source = doc["sources"][0]
    if mutation == "effect":
        source["fault_evidence"]["fault"]["effect_observed"] = False
    if mutation == "nominal":
        source["fault_evidence"]["nominal_regression_passed"] = True
    if mutation == "request":
        source["fault_request"]["requested_virtual_ms"] = 23
    if mutation == "error":
        source["native_errors"] = []
    if mutation in ("counter", "irq"):
        source["gpio_evidence"]["model_observations"][0][
            "timer_counter" if mutation == "counter" else "interrupt_enable"
        ] += 1
    if mutation == "span":
        source["gpio_observation_spans"][0]["byte_end"] += 1
    if mutation == "newline":
        span = source["gpio_observation_spans"][-1]
        raw = base64.b64decode(span["raw_base64"])[:-2]
        span.update(
            raw_base64=base64.b64encode(raw).decode(),
            sha256=digest(raw),
            byte_end=span["byte_end"] - 2,
        )
    if mutation == "coverage":
        source["physical_timing_verified"] = True
    with pytest.raises(TraceError):
        validate(doc)


@pytest.mark.parametrize(
    "mutation", ["request", "counter", "irq", "bad-bool", "unknown-fault", "partial-line"]
)
def test_import_binds_fault_request_and_raw_counter_irq(tmp_path, mutation):
    path = fault_report(tmp_path / "native")
    native = json.loads(path.read_bytes())
    if mutation == "request":
        plan = json.loads((path.parent / "plan.json").read_bytes())
        plan["scenario"]["fault"]["requested_virtual_ms"] = 23
        raw = json.dumps(plan).encode()
        (path.parent / "plan.json").write_bytes(raw)
        native["artifacts"]["plan.json"].update(sha256=digest(raw), bytes=len(raw))
        native["plan_sha256"] = digest(raw)
    if mutation in ("counter", "irq"):
        native["assertions"]["model_observations"][0][
            "timer_counter" if mutation == "counter" else "interrupt_enable"
        ] += 1
    if mutation == "bad-bool":
        native["assertions"]["fault"]["effect_observed"] = 1
    if mutation == "unknown-fault":
        native["fault_scenario"] = "arbitrary-command"
    if mutation == "partial-line":
        raw = (path.parent / "backend.stdout.bin").read_bytes()[:-2]
        (path.parent / "backend.stdout.bin").write_bytes(raw)
        native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))
