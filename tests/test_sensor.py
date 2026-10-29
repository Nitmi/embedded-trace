"""Synthetic sensor declarations and byte provenance; never execute native policy."""

import base64
import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import SENSOR_FIELDS, SENSOR_LABELS, SENSOR_PROFILE
from embedded_trace.timeline import correlate


def sensor_report(root, fault="none", unknown=False):
    path = evidence(root, qemu=False)
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    temperatures = (
        [25, -10, 85, 25]
        if fault == "none"
        else ([25, 25, 25, 25] if fault == "temperature-stuck" else [25, 0, 95, 35])
    )
    rows, samples = [], []
    stdout = b"[INFO] path \xff\r\n"
    for i, value in enumerate(temperatures):
        raw = f"SIM_SENSOR_OBS_{i}\r\n{value}\r\n72\r\n{5000 * (i + 1)}\r\n".encode()
        rows.append(
            dict(
                phase=i,
                requested_virtual_ms=20 + 20 * i,
                temperature_celsius=value,
                i2c_address=72,
                timer_counter=5000 * (i + 1),
                stdout_offset=len(stdout),
                stdout_bytes=len(raw),
                stdout_sha256=digest(raw),
            )
        )
        stdout += raw
        for j in range(4):
            sequence = i * 4 + j + 1
            samples.append(
                dict(
                    sequence=sequence,
                    raw_byte=value & 255,
                    celsius=value,
                    timer_ticks=1250 * sequence,
                    irq_vector=24,
                    error=0,
                )
            )
    passed = fault == "none" and not unknown
    declarations = dict(
        nominal_regression_passed=passed,
        nominal_failure=None if passed else "synthetic native failure",
        fault=dict(
            id=fault,
            effect_observed=None if fault == "none" else True,
            status="not_requested" if fault == "none" else "observed",
        ),
        samples=samples,
        model_observations=rows,
        fault_scenario=fault,
        **SENSOR_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.sensor-report.v1",
        profile=SENSOR_PROFILE,
        fault_scenario=fault,
        **SENSOR_LABELS,
        assertions=None if unknown else declarations,
        ok=passed,
        status="passed" if passed else "failed",
        errors=[]
        if passed
        else [
            dict(
                code="TIMEOUT" if unknown else "ASSERTION_FAILED",
                message="synthetic native failure",
            )
        ],
        virtual_time=dict(domain="renode_emulation", requested_ms=82, completed=not unknown),
    )
    plan.update(
        schema_version="embedded-sim-runner.sensor-plan.v1",
        profile=SENSOR_PROFILE,
        backend="renode",
        virtual_ms=82,
        fault_scenario=fault,
        **SENSOR_LABELS,
        scenario=dict(fault=dict(id=fault, requested_virtual_ms=None if fault == "none" else 22)),
        script_sha256=digest((root / "run.resc").read_bytes()),
    )
    (root / "plan.json").write_text(json.dumps(plan))
    (root / "backend.stdout.bin").write_bytes(stdout)
    for name in ("plan.json", "backend.stdout.bin"):
        raw = (root / name).read_bytes()
        native["artifacts"][name].update(sha256=digest(raw), bytes=len(raw))
    native["plan_sha256"] = digest((root / "plan.json").read_bytes())
    path.write_text(json.dumps(native))
    return path


@pytest.mark.parametrize("fault", ["none", "temperature-stuck", "temperature-offset"])
@pytest.mark.parametrize("unknown", [False, True])
def test_sensor_failed_and_unknown_evidence_survives_offline_views(
    tmp_path, monkeypatch, fault, unknown
):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline spawned"))
    path = sensor_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["sensor_evidence"] == native["assertions"]
    assert source["native_errors"] == native["errors"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    stdout = (path.parent / "backend.stdout.bin").read_bytes()
    for span in source["sensor_observation_spans"]:
        assert base64.b64decode(span["raw_base64"]) == stdout[span["byte_start"] : span["byte_end"]]
    assert len(source["sensor_observation_spans"]) == (0 if unknown else 4)
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    path.rename(path.with_suffix(".moved"))
    (path.parent / "backend.stdout.bin").rename(path.parent / "stdout.moved")
    for result in (
        inspect(timeline, digest(timeline.read_bytes())),
        query(timeline, digest(timeline.read_bytes()), contains="HEARTBEAT"),
        query(timeline, digest(timeline.read_bytes()), contains="NO_SUCH_LINE"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert all(summary[k] == source[k] for k in SENSOR_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    output = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), output, contains="NO_SUCH_LINE")
    assert all(key in output.read_text() for key in SENSOR_FIELDS)


@pytest.mark.parametrize(
    "mutation",
    [
        "effect",
        "nominal",
        "celsius",
        "offset",
        "raw",
        "newline",
        "request",
        "errors",
        "coverage",
        "clock",
        "boolean",
    ],
)
def test_rehashed_timeline_cannot_change_sensor_declarations(tmp_path, mutation):
    doc = correlate(spec(sensor_report(tmp_path / "native", "temperature-offset")))
    source = doc["sources"][0]
    if mutation == "effect":
        source["sensor_evidence"]["fault"]["effect_observed"] = False
    if mutation == "nominal":
        source["sensor_evidence"]["nominal_regression_passed"] = True
    if mutation == "celsius":
        source["sensor_evidence"]["samples"][4]["celsius"] += 1
    if mutation == "offset":
        source["sensor_observation_spans"][0]["byte_start"] += 1
    if mutation in ("raw", "newline"):
        span = source["sensor_observation_spans"][0]
        raw = base64.b64decode(span["raw_base64"])
        raw = raw.replace(b"25", b"26", 1) if mutation == "raw" else raw[:-2]
        span.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "request":
        source["fault_request"]["requested_virtual_ms"] = 23
    if mutation == "errors":
        source["native_errors"] = []
    if mutation == "coverage":
        source["sensor_accuracy_verified"] = True
    if mutation == "clock":
        source["virtual_time"]["requested_ms"] += 1
    if mutation == "boolean":
        source["sensor_evidence"]["samples"][0]["celsius"] = True
    with pytest.raises(TraceError):
        validate(doc)


@pytest.mark.parametrize("mutation", ["raw", "offset", "overflow", "partial", "bool", "request"])
def test_import_rejects_coherently_rehashed_inconsistent_sensor_input(tmp_path, mutation):
    path = sensor_report(tmp_path / "native")
    native = json.loads(path.read_bytes())
    if mutation in ("offset", "overflow", "bool"):
        row = native["assertions"]["model_observations"][0]
        row[
            {"offset": "stdout_offset", "overflow": "temperature_celsius", "bool": "timer_counter"}[
                mutation
            ]
        ] = {"offset": row["stdout_offset"] + 1, "overflow": 128, "bool": True}[mutation]
    if mutation in ("raw", "partial"):
        stdout = path.parent / "backend.stdout.bin"
        raw = stdout.read_bytes()
        raw = raw.replace(b"25", b"26", 1) if mutation == "raw" else raw[:-2]
        stdout.write_bytes(raw)
        native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    if mutation == "request":
        plan_path = path.parent / "plan.json"
        plan = json.loads(plan_path.read_bytes())
        plan["scenario"]["fault"]["requested_virtual_ms"] = 22
        plan_path.write_text(json.dumps(plan))
        raw = plan_path.read_bytes()
        native["plan_sha256"] = digest(raw)
        native["artifacts"]["plan.json"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))


def test_failed_native_values_are_not_reevaluated_as_a_new_policy(tmp_path):
    path = sensor_report(tmp_path / "native", "temperature-stuck")
    native = json.loads(path.read_bytes())
    native["assertions"]["samples"][0]["celsius"] = 246  # valid failed native declaration
    path.write_text(json.dumps(native))
    doc = correlate(spec(path))
    assert doc["sources"][0]["sensor_evidence"]["samples"][0]["celsius"] == 246
    assert doc["sources"][0]["capture_outcome"] == "failed"
