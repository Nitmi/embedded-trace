"""SPI saved structure and byte spans; no execution or native policy evaluation."""

import base64
import json
from decimal import Decimal

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import SPI_FIELDS, SPI_LABELS, SPI_PROFILE
from embedded_trace.timeline import correlate


def spi_report(root, fault="none", unknown=False):
    path = evidence(
        root,
        qemu=False,
        passed=fault == "none" and not unknown,
        uart=None if unknown else b"SAMPLE 00000001\r\n",
    )
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    stdout = b"[INFO] synthetic SPI\r\n"
    rows = []
    samples = []
    slip = None
    for i, t in enumerate((401, -162, 1368, 1)):
        if i == 1 and fault == "frame-slip":
            raw = b"SIM_SPI_SLIP\r\n250\r\n"
            slip = dict(
                requested_virtual_ms=22,
                discarded_byte=250,
                stdout_offset=len(stdout),
                stdout_bytes=len(raw),
                stdout_sha256=digest(raw),
            )
            stdout += raw
        if fault == "temperature-stuck":
            t = 401
        raw = f"SIM_SPI_OBS_{i}\r\n{Decimal(t) / 16}\r\n1\r\n{(i + 1) * 5000}\r\n".encode()
        rows.append(
            dict(
                phase=i,
                requested_virtual_ms=20 + i * 20,
                temperature_q4=t,
                spi_enabled=1,
                timer_counter=(i + 1) * 5000,
                stdout_offset=len(stdout),
                stdout_bytes=len(raw),
                stdout_sha256=digest(raw),
            )
        )
        stdout += raw
        samples.append(
            dict(
                sequence=i + 1,
                raw_word=((t << 3) | 7) & 65535,
                temperature_q4=t,
                timer_ticks=(i + 1) * 1250,
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
        frame_slip_observation=slip,
        fault_scenario=fault,
        **SPI_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.spi-sensor-report.v1",
        profile=SPI_PROFILE,
        fault_scenario=fault,
        **SPI_LABELS,
        assertions=None if unknown else declarations,
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
        schema_version="embedded-sim-runner.spi-sensor-plan.v1",
        runner_version="0.9.0",
        profile=SPI_PROFILE,
        backend="renode",
        virtual_ms=82,
        fault_scenario=fault,
        **SPI_LABELS,
        scenario=dict(fault=dict(id=fault, requested_virtual_ms=None if fault == "none" else 22)),
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


@pytest.mark.parametrize("fault", ("none", "temperature-stuck", "frame-slip"))
@pytest.mark.parametrize("unknown", (False, True))
def test_spi_evidence_survives_full_filtered_and_empty_offline_views(
    tmp_path, monkeypatch, fault, unknown
):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("offline spawned"))
    path = spi_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["sensor_evidence"] == native["assertions"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert "i2c_electrical_behavior_verified" not in source
    stdout = (path.parent / "backend.stdout.bin").read_bytes()
    for span in [
        *source["sensor_observation_spans"],
        *([source["spi_frame_slip_span"]] if source["spi_frame_slip_span"] else []),
    ]:
        assert base64.b64decode(span["raw_base64"]) == stdout[span["byte_start"] : span["byte_end"]]
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    # Every view must be self-contained, even with original sources removed.
    path.rename(path.with_suffix(".moved"))
    (path.parent / "backend.stdout.bin").rename(path.parent / "stdout.moved")
    for result in (
        inspect(timeline, digest(timeline.read_bytes())),
        query(timeline, digest(timeline.read_bytes()), contains="SAMPLE"),
        query(timeline, digest(timeline.read_bytes()), contains="NO_SUCH_LINE"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert all(summary[k] == source[k] for k in SPI_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    output = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), output, contains="NO_SUCH_LINE")
    assert all(k in output.read_text() for k in SPI_FIELDS)


@pytest.mark.parametrize(
    "mutation",
    (
        "q4",
        "word",
        "boolean",
        "effect",
        "coverage",
        "request",
        "clock",
        "span-offset",
        "span-raw",
        "slip-missing",
        "slip-byte",
        "slip-raw",
        "slip-order",
    ),
)
def test_rehashed_timeline_cannot_relabel_spi_or_slip(tmp_path, mutation):
    doc = correlate(spec(spi_report(tmp_path / "native", "frame-slip")))
    s = doc["sources"][0]
    if mutation in ("q4", "word", "boolean"):
        s["sensor_evidence"]["samples"][0][
            "temperature_q4" if mutation != "word" else "raw_word"
        ] = True if mutation == "boolean" else 123
    if mutation == "effect":
        s["sensor_evidence"]["fault"]["effect_observed"] = False
    if mutation == "coverage":
        s["spi_electrical_behavior_verified"] = True
    if mutation == "request":
        s["fault_request"]["requested_virtual_ms"] = 23
    if mutation == "clock":
        s["virtual_time"]["requested_ms"] = 83
    if mutation == "span-offset":
        s["sensor_observation_spans"][0]["byte_start"] += 1
    if mutation == "span-raw":
        span = s["sensor_observation_spans"][0]
        raw = base64.b64decode(span["raw_base64"]).replace(b"25.0625", b"25.1250")
        span.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "slip-missing":
        s.pop("spi_frame_slip_span")
    if mutation == "slip-byte":
        s["sensor_evidence"]["frame_slip_observation"]["discarded_byte"] = 249
    if mutation == "slip-raw":
        span = s["spi_frame_slip_span"]
        raw = base64.b64decode(span["raw_base64"]).replace(b"250", b"249")
        span.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "slip-order":
        s["spi_frame_slip_span"]["byte_start"] = 0
    with pytest.raises(TraceError):
        validate(doc)


@pytest.mark.parametrize(
    "mutation", ("raw", "partial", "bool", "range", "producer", "fault", "slip-byte")
)
def test_import_rejects_rehashed_inconsistent_raw_and_context(tmp_path, mutation):
    path = spi_report(tmp_path / "native", "frame-slip")
    native = json.loads(path.read_bytes())
    if mutation in ("raw", "partial"):
        p = path.parent / "backend.stdout.bin"
        raw = p.read_bytes()
        raw = raw.replace(b"25.0625", b"25.1250") if mutation == "raw" else raw[:-2]
        p.write_bytes(raw)
        native["artifacts"][p.name].update(sha256=digest(raw), bytes=len(raw))
    if mutation in ("bool", "range"):
        native["assertions"]["model_observations"][0]["temperature_q4"] = (
            True if mutation == "bool" else 2401
        )
    if mutation == "slip-byte":
        native["assertions"]["frame_slip_observation"]["discarded_byte"] = 256
    if mutation == "fault":
        native["fault_scenario"] = "temperature-offset"
    if mutation == "producer":
        p = path.parent / "plan.json"
        plan = json.loads(p.read_bytes())
        plan["runner_version"] = "0.8.0"
        p.write_text(json.dumps(plan))
        raw = p.read_bytes()
        native["artifacts"][p.name].update(sha256=digest(raw), bytes=len(raw))
        native["plan_sha256"] = digest(raw)
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))


def test_failed_native_q4_is_preserved_without_reapplying_regression_policy(tmp_path):
    path = spi_report(tmp_path / "native", "frame-slip")
    native = json.loads(path.read_bytes())
    native["assertions"]["samples"][0]["temperature_q4"] = 123456
    native["assertions"]["fault"].update(effect_observed=None, status="unknown")
    path.write_text(json.dumps(native))
    doc = correlate(spec(path))
    assert doc["sources"][0]["sensor_evidence"]["samples"][0]["temperature_q4"] == 123456
    assert doc["sources"][0]["capture_outcome"] == "failed"
