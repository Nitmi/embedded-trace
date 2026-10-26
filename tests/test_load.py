"""Offline load views preserve the complete verdict under filters and edits."""

import base64
import json
import socket
import subprocess
from pathlib import Path

import jsonschema
import pytest

from embedded_trace import load
from embedded_trace import load_protocol as protocol
from embedded_trace.cli import main
from embedded_trace.common import TraceError, digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/load"


def case(root, scenario="mixed"):
    path = root / "bundle.json"
    path.write_bytes((EXAMPLES / (scenario + ".json")).read_bytes())
    return path, digest(path.read_bytes())


@pytest.mark.parametrize("scenario", ["passed", "failed", "invalid", "mixed", "cleanup", "timeout"])
def test_native_context_raw_bytes_schema_and_complete_verdict(tmp_path, scenario, monkeypatch):
    path, sha = case(tmp_path, scenario)

    def forbidden(*a, **kw):
        raise AssertionError("no device/execution")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    calls = []
    original = load.read_file

    def once(*a, **kw):
        calls.append(a[0])
        return original(*a, **kw)

    monkeypatch.setattr(load, "read_file", once)
    view = load.view(path, sha)
    assert len(calls) == 1 and view["verdict"]["ok"] is (scenario == "passed")
    assert all(view[k] is False for k in protocol.FLAGS)
    assert (
        view["hil_import_checks_reperformed"]
        is view["clock_alignment_verified"]
        is view["source_files_rechecked"]
        is False
    )
    assert view["time_semantics"] == protocol.TIME
    schema = json.loads((EXAMPLES.parents[1] / "schemas/load-report.schema.json").read_bytes())
    jsonschema.validate(json.loads(path.read_bytes()), schema)
    if scenario in ("timeout", "cleanup"):
        assert view["source"]["recorded_cleanup"]["instrument_state"] == "unknown"
        assert view["junit"]["errors"] == 1
    if scenario == "cleanup":
        assert len(view["source"]["recorded_partial_measurements"]) == 1
    if scenario == "passed":
        query = view["checks"][0]["measurements"][0]["raw_queries"][0]
        assert base64.b64decode(query["rx_base64"]).endswith(b"\r\n")


@pytest.mark.parametrize("scenario", ["failed", "invalid", "mixed", "cleanup", "timeout"])
@pytest.mark.parametrize(
    "selection", [{"status": "passed"}, {"phase": "observe"}, {"check": "absent"}, {"offset": 8}]
)
def test_passing_only_and_empty_pages_never_mask_global_failure(tmp_path, scenario, selection):
    path, sha = case(tmp_path, scenario)
    full = load.view(path, sha)
    filtered = load.view(path, sha, **selection)
    assert filtered["verdict"] == full["verdict"] and filtered["junit"] == full["junit"]
    assert not filtered["verdict"]["ok"]
    if selection != {"status": "passed"} or scenario != "mixed":
        assert filtered["checks"] == []
    else:
        assert len(filtered["checks"]) == 1 and filtered["checks"][0]["ok"]


@pytest.mark.parametrize(
    "mode",
    [
        "verdict",
        "summary",
        "source",
        "metric",
        "flag",
        "raw",
        "native",
        "producer",
        "input-roles",
        "native-exit",
        "xml-ref",
    ],
)
def test_rehashed_bundle_changes_do_not_override_embedded_evidence(tmp_path, mode):
    path, _ = case(tmp_path, "passed")
    bundle = json.loads(path.read_bytes())
    if mode == "verdict":
        bundle["ok"] = False
    elif mode == "summary":
        bundle["summary"]["passed"] = 0
    elif mode == "source":
        bundle["source"]["recorded_cleanup"]["complete"] = False
    elif mode == "metric":
        bundle["checks"][0]["metrics"]["mean_voltage_v"] += 0.1
    elif mode == "flag":
        bundle["calibration_verified"] = True
    elif mode == "raw":
        bundle["inputs"]["transcript"]["raw_base64"] = "AA=="
    elif mode == "native":
        bundle["native_recomputation_recorded"] = False
    elif mode == "producer":
        bundle["producer_version"] = "99.0.0"
    elif mode == "input-roles":
        bundle["inputs"].pop("plan")
    elif mode == "native-exit":
        bundle["native_exit_code"] = 3
    else:
        bundle["inputs"]["junit"]["sha256"] = "0" * 64
    path.write_bytes(protocol.canonical(bundle))
    with pytest.raises((ValueError, TraceError)):
        load.view(path, digest(path.read_bytes()))


@pytest.mark.parametrize(
    "filters",
    [
        {"offset": True},
        {"offset": 9},
        {"limit": 0},
        {"limit": 9},
        {"phase": "auto"},
        {"status": "skipped"},
        {"check": ""},
    ],
)
def test_invalid_filters_fail_before_bundle_read(tmp_path, filters, monkeypatch):
    monkeypatch.setattr(load, "load", lambda *a: pytest.fail("must not read"))
    with pytest.raises((ValueError, TraceError)):
        load.view(tmp_path / "absent", "0" * 64, **filters)


def test_markdown_always_keeps_global_counts_and_inert_limited_context(tmp_path):
    path, sha = case(tmp_path, "cleanup")
    output = tmp_path / "view.md"
    viewed = load.markdown(path, sha, output, status="passed")
    text = output.read_text("ascii")
    assert "Global verdict: failed" in text and '"errors": 1' in text
    assert viewed["checks"] == [] and viewed["junit"]["errors"] == 1
    assert digest(output.read_bytes()) == viewed["output"]["sha256"]
    assert len(output.read_bytes()) <= 1048576
    with pytest.raises(TraceError):
        load.markdown(tmp_path / "missing", "0" * 64, output)


def test_cli_processing_succeeds_with_failed_test_and_query_empty(tmp_path, capsys):
    path, sha = case(tmp_path)
    assert main(["load", "query", str(path), "--sha256", sha, "--status", "passed", "--json"]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["ok"] and not response["data"]["verdict"]["ok"]
    assert response["data"]["junit"]["failures"] == 1 and response["data"]["selected_checks"] == 1


@pytest.mark.parametrize(
    "missing",
    [
        "embedded_trace/load.py",
        "embedded_trace/load_protocol.py",
        "embedded_trace/schemas/load-report.schema.json",
    ],
)
def test_release_exact_inventory_requires_new_payloads(tmp_path, missing):
    from test_release import REVISION, archives

    from scripts import release

    archives(tmp_path, version="0.11.0", mutate=lambda w, s: w.pop(missing))
    with pytest.raises(ValueError, match="Unexpected/missing wheel"):
        release.create_manifest(tmp_path, "0.11.0", REVISION)


@pytest.mark.parametrize(
    "domain,scenario",
    [
        (d, s)
        for d, ss in (
            ("instrument", ("passed", "failed", "invalid", "mixed", "legacy")),
            ("waveform", ("passed", "failed", "invalid")),
        )
        for s in ss
    ],
)
def test_actual_lab10_digital_and_waveform_compatibility(domain, scenario):
    from embedded_trace import instrument, waveform

    path = EXAMPLES.parent / (domain + "-10") / (scenario + ".json")
    selected = {"instrument": instrument, "waveform": waveform}[domain]
    view = selected.view(path, digest(path.read_bytes()), status="passed")
    assert view["verdict"]["ok"] is (scenario in ("passed", "legacy"))
    assert not view["native_recomputed_now"] and not view["source_files_rechecked"]
