"""Offline S3 provenance tests; never execute or import a simulator."""

import copy
import json
import shutil

import pytest
from test_simulation import evidence, spec

from embedded_trace.common import TraceError, digest
from embedded_trace.query import inspect, query, validate
from embedded_trace.report import report as render
from embedded_trace.simulation import S3_FIELDS
from embedded_trace.timeline import correlate


def s3_evidence(root, *, passed=True):
    path = evidence(root, flash=True, passed=passed)
    native = json.loads(path.read_bytes())
    files = {name: (root / name).read_bytes() for name in native["artifacts"]}
    files["esp32s3_rev0_rom.bin"] = files.pop("esp32c3-rom.bin")
    model = {"backend": "espressif-qemu-xtensa", "profile": "esp32s3-idf-flash-v1"}
    files["model.json"] = json.dumps(model).encode()
    runtime = {
        "backend": model["backend"],
        "version": "synthetic-xtensa",
        "archive_sha256": "a" * 64,
        "executable": "bin/qemu-system-xtensa.exe",
        "files": {"share/qemu/esp32s3_rev0_rom.bin": digest(files["esp32s3_rev0_rom.bin"])},
    }
    files["runtime-lock.json"] = json.dumps(runtime).encode()
    plan = json.loads(files["plan.json"])
    plan.update(
        schema_version="embedded-sim-runner.qemu-s3-flash-plan.v1",
        **model,
        backend_version=runtime["version"],
        model_sha256=digest(files["model.json"]),
        runtime_lock={"sha256": digest(files["runtime-lock.json"])},
    )
    files["plan.json"] = json.dumps(plan).encode()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    native.update(
        schema_version="embedded-sim-runner.qemu-s3-flash-report.v1",
        **model,
        backend_version=runtime["version"],
        runtime_archive_sha256=runtime["archive_sha256"],
        virtual_time={
            "domain": "qemu_device_clock_unmeasured",
            "elapsed_ns": None,
            "budget_enforced": False,
        },
        plan_sha256=digest(files["plan.json"]),
        runtime_lock_sha256=digest(files["runtime-lock.json"]),
        artifacts={
            name: {"path": "Z:/ignored/" + name, "sha256": digest(raw), "bytes": len(raw)}
            for name, raw in files.items()
        },
    )
    if passed:
        # Shape is checked, native core/readiness policy is not rerun by Trace.
        native["assertions"]["app_core_markers"] = [1]
    path.write_text(json.dumps(native))
    return path


@pytest.mark.parametrize("passed", [True, False])
def test_s3_keeps_limits_identity_null_and_unmeasured_time_offline(tmp_path, monkeypatch, passed):
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: pytest.fail("offline process launch"))
    path = s3_evidence(tmp_path / "native", passed=passed)
    doc = correlate(spec(path))
    validate(doc)
    source = doc["sources"][0]
    assert source["backend"] == "espressif-qemu-xtensa"
    assert source["app_core_markers"] == ([1] if passed else None)
    assert source["virtual_time"]["elapsed_ns"] is None
    assert source["capture_outcome"] == ("succeeded_with_model_limits" if passed else "failed")
    assert source["extra_input_bytes"] > 8 * 1024 * 1024
    saved = tmp_path / "timeline.json"
    saved.write_text(json.dumps(doc))
    shutil.rmtree(path.parent)
    for result in (
        inspect(saved, digest(saved.read_bytes())),
        query(saved, digest(saved.read_bytes()), contains="HEARTBEAT", limit=1),
        render(saved, digest(saved.read_bytes()), tmp_path / "report.md"),
    ):
        summary = result["simulation_sources"]["sim"]
        assert all(summary[key] == source[key] for key in S3_FIELDS)
        assert summary["model_coverage_complete"] is summary["security_features_verified"] is False
    assert "qemu_device_clock_unmeasured" in (tmp_path / "report.md").read_text()


@pytest.mark.parametrize(
    "key,value",
    [
        ("backend", "espressif-qemu"),
        ("backend_version", "other"),
        ("runtime_archive_sha256", "b" * 64),
        ("app_core_markers", [True]),
        ("model_diagnostics", []),
        ("model_coverage_complete", 0),
        (
            "virtual_time",
            {"domain": "qemu_icount_shift_0", "elapsed_ns": None, "budget_enforced": False},
        ),
    ],
)
def test_s3_timeline_summary_cannot_be_relabelled(tmp_path, key, value):
    doc = correlate(spec(s3_evidence(tmp_path / "native")))
    changed = copy.deepcopy(doc)
    changed["sources"][0][key] = value
    with pytest.raises(TraceError):
        validate(changed)


@pytest.mark.parametrize(
    "mutation", ["clock", "budget-type", "backend", "runtime-archive", "executable", "model", "rom"]
)
def test_s3_import_rejects_inconsistent_identity_or_clock(tmp_path, mutation):
    path = s3_evidence(tmp_path / "native")
    report = json.loads(path.read_bytes())
    if mutation == "clock":
        report["virtual_time"]["elapsed_ns"] = 1000
    elif mutation == "budget-type":
        report["virtual_time"]["budget_enforced"] = 0
    elif mutation == "backend":
        report["backend"] = "espressif-qemu"
    else:
        leaf = (
            "runtime-lock.json"
            if mutation in ("runtime-archive", "executable", "rom")
            else "model.json"
        )
        value = json.loads((path.parent / leaf).read_bytes())
        if mutation == "runtime-archive":
            value["archive_sha256"] = "b" * 64
        if mutation == "executable":
            value["executable"] = "bin/qemu-system-riscv32.exe"
        if mutation == "rom":
            value["files"]["share/qemu/esp32s3_rev0_rom.bin"] = "b" * 64
        if mutation == "model":
            value["backend"] = "espressif-qemu"
        raw = json.dumps(value).encode()
        (path.parent / leaf).write_bytes(raw)
        report["artifacts"][leaf].update(sha256=digest(raw), bytes=len(raw))
        plan_path = path.parent / "plan.json"
        plan = json.loads(plan_path.read_bytes())
        if leaf == "runtime-lock.json":
            plan["runtime_lock"]["sha256"] = report["runtime_lock_sha256"] = digest(raw)
        else:
            plan["model_sha256"] = digest(raw)
        raw = json.dumps(plan).encode()
        plan_path.write_bytes(raw)
        report["plan_sha256"] = digest(raw)
        report["artifacts"]["plan.json"].update(sha256=digest(raw), bytes=len(raw))
    path.write_text(json.dumps(report))
    with pytest.raises(TraceError):
        correlate(spec(path))
