from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from zipfile import ZipFile

import jsonschema
import pytest

from embedded_trace import thermal
from embedded_trace.cli import main
from embedded_trace.common import digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/thermal/fixtures.zip"
CASES = (
    "passed",
    "failed",
    "invalid",
    "mixed",
    "invalid-pixel",
    "mask-drift",
    "ffc-change",
    "duplicate",
    "source-failed",
    "cleanup-unknown",
    "no-pixels",
)


def case(root, scenario="mixed"):
    path = root / "bundle.json"
    with ZipFile(EXAMPLES) as z:
        assert z.getinfo(scenario + ".json").file_size <= 32 * 1024 * 1024
        path.write_bytes(z.read(scenario + ".json"))
    return path, digest(path.read_bytes())


@pytest.mark.parametrize("scenario", CASES)
def test_native_context_original_bytes_and_no_dependencies(tmp_path, scenario, monkeypatch):
    path, sha = case(tmp_path, scenario)

    def forbidden(*a, **kw):
        pytest.fail("no execution or devices in Trace")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    view = thermal.view(path, sha)
    assert view["verdict"]["ok"] is (scenario == "passed")
    assert view["source"]["evidence_origin"] == "test_double"
    assert (
        not view["hil_import_checks_reperformed"]
        and not view["native_temperature_conversion_performed"]
    )
    assert not view["calibration_verified"]
    jsonschema.validate(
        json.loads(path.read_bytes()),
        json.loads((EXAMPLES.parents[2] / "schemas/thermal-report.schema.json").read_bytes()),
    )


@pytest.mark.parametrize("selection", [{"status": "passed"}, {"offset": 8}, {"check": "absent"}])
def test_passing_only_and_empty_pages_preserve_global_failure(tmp_path, selection):
    path, sha = case(tmp_path)
    value = thermal.view(path, sha, **selection)
    assert not value["verdict"]["ok"]
    assert value["verdict"]["summary"]["failed"] == value["junit"]["failures"] == 1
    assert value["selected_checks"] == (1 if selection == {"status": "passed"} else 0)


@pytest.mark.parametrize(
    "mode", ["verdict", "source", "row", "flag", "missing", "origin", "version"]
)
def test_rehashed_bundle_edits_fail(tmp_path, mode):
    path, _ = case(tmp_path)
    value = json.loads(path.read_bytes())
    if mode == "verdict":
        value["ok"] = True
    if mode == "source":
        value["source"]["apparent_surface_temperature_only"] = False
    if mode == "row":
        value["checks"][0]["frames"][0]["roi"]["mean_c"] = 100
    if mode == "flag":
        value["radiometric_accuracy_verified"] = True
    if mode == "missing":
        value["source_files"].pop("native/frame-0000.y16")
    if mode == "origin":
        value["source"]["evidence_origin"] = "physical"
    if mode == "version":
        value["producer_version"] = "0.11.0"
    path.write_bytes(thermal.canonical(value))
    with pytest.raises((ValueError, KeyError)):
        thermal.view(path, digest(path.read_bytes()))


@pytest.mark.parametrize(
    "filters", [{"status": "skip"}, {"offset": 9}, {"limit": 0}, {"check": ""}]
)
def test_invalid_filters_fail_before_read(tmp_path, filters, monkeypatch):
    monkeypatch.setattr(thermal, "load", lambda *a: pytest.fail("must not read"))
    with pytest.raises(ValueError):
        thermal.view(tmp_path / "missing", "0" * 64, **filters)


def test_markdown_counts_and_cli_do_not_mask_failure(tmp_path, capsys):
    path, sha = case(tmp_path)
    output = tmp_path / "view.md"
    thermal.markdown(path, sha, output, status="passed")
    text = output.read_text()
    assert "Global verdict: failed" in text and '"failures": 1' in text
    assert "preview truncated" in text
    assert (
        main(["thermal", "query", str(path), "--sha256", sha, "--status", "passed", "--json"]) == 0
    )
    response = json.loads(capsys.readouterr().out)
    assert response["ok"] and not response["data"]["verdict"]["ok"]
    assert (
        main(["thermal", "report", str(path), "--sha256", sha, "--output", str(output), "--json"])
        == 2
    )
    assert not json.loads(capsys.readouterr().out)["ok"]


@pytest.mark.parametrize(
    "missing",
    [
        "embedded_trace/thermal.py",
        "embedded_trace/thermal_protocol.py",
        "embedded_trace/schemas/thermal-report.schema.json",
    ],
)
def test_release_requires_thermal_payloads(tmp_path, missing):
    from test_release import REVISION, archives, release

    archives(tmp_path, version="0.12.0", mutate=lambda w, s: w.pop(missing))
    with pytest.raises(ValueError, match="Unexpected/missing wheel"):
        release.create_manifest(tmp_path, "0.12.0", REVISION)
