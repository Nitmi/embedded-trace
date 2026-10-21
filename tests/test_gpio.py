"""Synthetic GPIO summaries exercise offline provenance, not simulator policy."""

import json

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import GPIO_LABELS, GPIO_PROFILE
from embedded_trace.timeline import correlate


def gpio_report(root, passed=True):
    path = evidence(root, qemu=False, passed=passed)
    doc = json.loads(path.read_bytes())
    plan = json.loads((root / "plan.json").read_bytes())
    coverage = {"model_coverage_complete": False, "physical_timing_verified": False, **GPIO_LABELS}
    plan.update(
        schema_version="embedded-sim-runner.gpio-timer-plan.v1",
        profile=GPIO_PROFILE,
        script_sha256=digest((root / "run.resc").read_bytes()),
        **coverage,
    )
    (root / "plan.json").write_text(json.dumps(plan))
    observations = []
    stdout = b"[INFO] Including D:/\xd1\xe9\xca\xd5/run.resc\r\n"
    for phase in range(4):
        value = 26624 if phase % 2 else 0
        observations.append(
            {
                "phase": phase,
                "requested_virtual_ms": 20 * (phase + 1),
                "out_register": value,
                "in_register": value,
            }
        )
        stdout += f"SIM_GPIO_OBS_{phase}\r\n{value}\r\n{value}\r\n".encode()
    (root / "backend.stdout.bin").write_bytes(stdout)
    for name in ("plan.json", "backend.stdout.bin"):
        raw = (root / name).read_bytes()
        doc["artifacts"][name].update(sha256=digest(raw), bytes=len(raw))
    doc.update(
        schema_version="embedded-sim-runner.gpio-timer-report.v1",
        profile=GPIO_PROFILE,
        plan_sha256=digest((root / "plan.json").read_bytes()),
        virtual_time={"domain": "renode_emulation", "requested_ms": 82, "completed": True},
        assertions={
            # Deliberately not a native-policy-positive fixture. Trace only
            # preserves bounded declarations; it must not emulate/rejudge them.
            "samples": [
                {
                    "sequence": 1,
                    "input": 0,
                    "output": 0,
                    "loopback": 0,
                    "timer_ticks": 99,
                    "irq_vector": 24,
                }
            ],
            "model_observations": observations,
        }
        if passed
        else None,
        **coverage,
    )
    path.write_text(json.dumps(doc))
    return path


@pytest.mark.parametrize("passed", [True, False])
def test_gpio_summary_spans_and_clocks_survive_offline_import(tmp_path, monkeypatch, passed):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline import spawned"))
    path = gpio_report(tmp_path / "native", passed)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["recorded_status"] == ("passed" if passed else "failed")
    assert source["capture_outcome"] == ("succeeded" if passed else "failed")
    assert doc["status"] == "correlated_with_warnings"
    assert source["model_coverage_complete"] is source["physical_timing_verified"] is False
    assert source["native_assertions_reexecuted"] is False
    assert source["timer_observation_semantics"] == GPIO_LABELS["timer_observation_semantics"]
    assert source["gpio_evidence"]["samples"] == (
        None if not passed else json.loads(path.read_bytes())["assertions"]["samples"]
    )
    assert len(source["gpio_observation_spans"]) == (4 if passed else 0)
    for event in doc["events"]:
        if event["kind"] == "line":
            assert event["time"] == source["host_window"]
    timeline = tmp_path / "timeline.json"
    timeline.write_text(json.dumps(doc))
    # Queries/rendering must work after the original logs disappear.
    path.rename(path.with_name("moved-original-report.json"))
    (path.parent / "backend.stdout.bin").rename(path.parent / "moved-stdout.bin")
    for result in (
        inspect(timeline, digest(timeline.read_bytes())),
        query(timeline, digest(timeline.read_bytes()), contains="HEARTBEAT"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert summary["gpio_evidence"] == source["gpio_evidence"]
        assert summary["gpio_observation_spans"] == source["gpio_observation_spans"]
        assert summary["physical_timing_verified"] is False
        assert summary["virtual_time"] == source["virtual_time"]
        assert summary["host_window"] == source["host_window"]
        assert summary["time_semantics"] == "simulation_run_host_window_not_uart_event_time"
        assert result["source_files_rechecked"] is False
    markdown = tmp_path / "gpio.md"
    render(timeline, digest(timeline.read_bytes()), markdown)
    rendered = markdown.read_text()
    assert (
        '"physical_timing_verified": false' in rendered and "gpio_observation_semantics" in rendered
    )
    if passed:
        assert "requested_virtual_ms" in rendered and "gpio_observation_spans" in rendered


@pytest.mark.parametrize(
    "mutation",
    [
        "sample",
        "snapshot",
        "coverage",
        "coverage-type",
        "timing",
        "label",
        "clock",
        "warning",
        "span",
        "span-content",
        "span-phase",
    ],
)
def test_rehashed_gpio_timeline_cannot_change_native_summary_or_span_layout(tmp_path, mutation):
    doc = correlate(spec(gpio_report(tmp_path / "native")))
    source = doc["sources"][0]
    if mutation == "sample":
        source["gpio_evidence"]["samples"][0]["timer_ticks"] = 250000
    if mutation == "snapshot":
        source["gpio_evidence"]["model_observations"][0]["requested_virtual_ms"] = 21
    if mutation == "coverage":
        source["model_coverage_complete"] = True
    if mutation == "coverage-type":
        source["model_coverage_complete"] = 0
    if mutation == "timing":
        source["physical_timing_verified"] = True
    if mutation == "label":
        source["timer_observation_semantics"] = "host_time"
    if mutation == "clock":
        source["virtual_time"]["requested_ms"] = 81
    if mutation == "warning":
        source["warnings"] = {}
        doc["status"] = "correlated"
    if mutation == "span":
        source["gpio_observation_spans"][0]["byte_end"] += 1
    if mutation == "span-content":
        source["gpio_observation_spans"][0]["raw_base64"] = "AA=="
    if mutation == "span-phase":
        source["gpio_observation_spans"][1]["phase"] = True
    with pytest.raises(TraceError):
        validate(doc)


@pytest.mark.parametrize(
    "mutation", ["snapshot", "script", "label", "shape", "oversize", "coverage"]
)
def test_import_binds_raw_model_observations_and_script_and_bounds_declarations(tmp_path, mutation):
    path = gpio_report(tmp_path / "native")
    doc = json.loads(path.read_bytes())
    if mutation == "snapshot":
        doc["assertions"]["model_observations"][1]["out_register"] = 0
    if mutation == "script":
        name = "run.resc"
        (path.parent / name).write_bytes(b"changed")
        doc["artifacts"][name].update(sha256=digest(b"changed"), bytes=7)
    if mutation == "label":
        doc["gpio_observation_semantics"] = "electrical_waveform"
    if mutation == "shape":
        doc["assertions"]["samples"][0]["input"] = True
    if mutation == "oversize":
        doc["assertions"]["samples"] *= 65
    if mutation == "coverage":
        doc["physical_timing_verified"] = True
    path.write_text(json.dumps(doc))
    with pytest.raises(TraceError):
        correlate(spec(path))


def test_gpio_evidence_summary_does_not_alias_native_metadata(tmp_path):
    doc = correlate(spec(gpio_report(tmp_path / "native")))
    source = doc["sources"][0]
    native = next(
        e["native"] for e in doc["events"] if e["kind"] == "native" and e["record_start"] == 1
    )
    assert source["gpio_evidence"] == {
        "samples": native["assertions"]["samples"],
        "model_observations": native["assertions"]["model_observations"],
    }
    # A serialized snapshot has separate summary and native metadata, even if
    # import internally reuses dictionaries before serialization.
    changed = json.loads(json.dumps(doc))
    changed["sources"][0]["gpio_evidence"]["model_observations"][0]["in_register"] = 1
    with pytest.raises(TraceError):
        validate(changed)
