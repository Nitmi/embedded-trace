"""Saved watchdog fields and raw spans; native firmware acceptance is not rerun."""

import base64
import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import WATCHDOG_FIELDS, WATCHDOG_LABELS, WATCHDOG_PROFILE
from embedded_trace.timeline import correlate


def watchdog_report(root, fault="none", unknown=False):
    counts = [4, 6] if fault == "feed-timer-stop" else [16]
    uart, boots, rows, resets = b"", [], [], []
    for count in counts:
        uart += b"READY\r\nBUILD abc\r\n"
        samples = []
        for seq in range(1, count + 1):
            running = int(fault != "watchdog-stop" or seq < 5)
            # A recorded bad running value must be retained, not reclassified by Trace.
            samples.append(
                dict(
                    sequence=seq,
                    partial_requests=2,
                    complete_requests=3,
                    running=running,
                    timer_ticks=seq * 1250,
                    irq_vector=24,
                )
            )
            uart += (
                f"SAMPLE {seq:08X} A=00000002 B=00000003 S={running:08X}"
                f" T={seq * 1250:08X} V=00000018\r\n"
            ).encode()
        boots.append(dict(samples=samples))
    path = evidence(root, qemu=False, passed=fault == "none" and not unknown, uart=uart)
    native = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    stdout = b""

    def record(raw):
        nonlocal stdout
        result = dict(stdout_offset=len(stdout), stdout_bytes=len(raw), stdout_sha256=digest(raw))
        stdout += raw
        return result

    for i, timer in enumerate(
        [5000, 5500, 2175, 7175] if fault == "feed-timer-stop" else [5000, 10000, 15000, 20000]
    ):
        if i == 1 and fault != "none":
            stdout += b"SIM_WDT_FAULT\r\n"
        if i == 2 and fault == "feed-timer-stop":
            reset = record(b"[00:00] [INFO] watchdog: Reseting machine\r\n")
            reset["callback"] = record(b"SIM_WDT_RESET_MACRO\r\n")
            resets.append(reset)
        running = int(fault != "watchdog-stop" or i == 0)
        raw = f"SIM_WDT_OBS_{i}\r\n{running}\r\n3\r\n1023\r\n3\r\n860\r\n{timer}\r\n".encode()
        rows.append(
            dict(
                phase=i,
                requested_virtual_ms=20 + i * 20,
                running=running,
                requests=3,
                reload_value=1023,
                reload_enabled=3,
                watchdog_counter=860,
                timer_counter=timer,
                **record(raw),
            )
        )
    passed = fault == "none" and not unknown
    declarations = dict(
        nominal_regression_passed=passed,
        nominal_failure=None if passed else "recorded failure",
        fault=dict(
            id=fault,
            effect_observed=None if fault == "none" else True,
            status="not_requested" if fault == "none" else "observed",
        ),
        boots=boots,
        model_observations=rows,
        reset_observations=resets,
        fault_scenario=fault,
        **WATCHDOG_LABELS,
    )
    native.update(
        schema_version="embedded-sim-runner.watchdog-report.v1",
        profile=WATCHDOG_PROFILE,
        fault_scenario=fault,
        **WATCHDOG_LABELS,
        assertions=None if unknown else declarations,
        errors=[]
        if passed
        else [dict(code="TIMEOUT" if unknown else "ASSERTION_FAILED", message="recorded failure")],
        virtual_time=dict(domain="renode_emulation", requested_ms=82, completed=not unknown),
    )
    plan.update(
        schema_version="embedded-sim-runner.watchdog-plan.v1",
        runner_version="0.10.0",
        profile=WATCHDOG_PROFILE,
        backend="renode",
        virtual_ms=82,
        fault_scenario=fault,
        **WATCHDOG_LABELS,
        scenario=dict(fault=dict(id=fault, requested_virtual_ms=None if fault == "none" else 22)),
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


@pytest.mark.parametrize("fault", ("none", "feed-timer-stop", "watchdog-stop"))
@pytest.mark.parametrize("unknown", (False, True))
def test_watchdog_survives_full_filtered_empty_and_moved_views(
    tmp_path, monkeypatch, fault, unknown
):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("offline spawned"))
    path = watchdog_report(tmp_path / "native", fault, unknown)
    native = json.loads(path.read_bytes())
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["watchdog_evidence"] == native["assertions"]
    assert source["capture_outcome"] == ("succeeded" if native["ok"] else "failed")
    assert len(source["watchdog_reset_spans"]) == (
        1 if fault == "feed-timer-stop" and not unknown else 0
    )
    for pair in source["watchdog_reset_spans"]:
        for span in pair.values():
            raw = (path.parent / "backend.stdout.bin").read_bytes()[
                span["byte_start"] : span["byte_end"]
            ]
            assert base64.b64decode(span["raw_base64"]) == raw
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
        assert all(summary[k] == source[k] for k in WATCHDOG_FIELDS)
        assert summary["recorded_status"] == native["status"]
        assert summary["native_assertions_reexecuted"] is False
    out = tmp_path / "report.md"
    render(timeline, digest(timeline.read_bytes()), out, contains="NO_SUCH_LINE")
    assert all(k in out.read_text() for k in WATCHDOG_FIELDS)


@pytest.mark.parametrize(
    "mutation",
    (
        "coverage",
        "effect",
        "clock",
        "sample",
        "sample-span",
        "model-span",
        "reset-span",
        "callback",
        "missing",
        "range",
        "overflow",
        "count",
        "request",
        "span-type",
    ),
)
def test_watchdog_rehashed_contradictions_are_rejected(tmp_path, mutation):
    path = watchdog_report(tmp_path / "native", "feed-timer-stop")
    doc = correlate(spec(path))
    source = doc["sources"][0]
    ev = source["watchdog_evidence"]
    if mutation == "coverage":
        source["physical_reset_verified"] = True
    if mutation == "effect":
        ev["fault"]["effect_observed"] = False
    if mutation == "clock":
        source["virtual_time"]["requested_ms"] = 83
    if mutation == "sample":
        ev["boots"][0]["samples"][0]["running"] = 0
    if mutation == "sample-span":
        source["watchdog_sample_spans"][0]["byte_start"] += 1
    if mutation == "model-span":
        span = source["watchdog_observation_spans"][0]
        raw = base64.b64decode(span["raw_base64"]).replace(b"1023", b"1022")
        span.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw))
    if mutation == "reset-span":
        source["watchdog_reset_spans"][0]["reset"]["byte_end"] += 1
    if mutation == "callback":
        source["watchdog_reset_spans"][0]["callback"]["byte_start"] = 0
    if mutation == "missing":
        source.pop("watchdog_reset_spans")
    if mutation == "range":
        ev["boots"][0]["samples"][0]["sequence"] = True
    if mutation == "overflow":
        ev["model_observations"][0]["timer_counter"] = 2**32
    if mutation == "count":
        source["watchdog_sample_spans"] *= 2
    if mutation == "request":
        source["fault_request"]["requested_virtual_ms"] = 23
    if mutation == "span-type":
        source["watchdog_sample_spans"][0] = 123
    with pytest.raises(TraceError):
        validate(doc)


def test_import_rejects_coherently_rehashed_contradictory_model_bytes(tmp_path):
    path = watchdog_report(tmp_path / "native", "feed-timer-stop")
    native = json.loads(path.read_bytes())
    raw = (path.parent / "backend.stdout.bin").read_bytes().replace(b"1023", b"1022", 1)
    (path.parent / "backend.stdout.bin").write_bytes(raw)
    native["artifacts"]["backend.stdout.bin"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(native))
    with pytest.raises(TraceError):
        correlate(spec(path))
