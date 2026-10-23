from __future__ import annotations

import base64
import json
import socket
import subprocess
from pathlib import Path

import pytest

from embedded_trace import instrument
from embedded_trace.cli import main
from embedded_trace.common import TraceError, digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/instrument"


def case(tmp_path, scenario="mixed"):
    path = tmp_path / "bundle.json"
    path.write_bytes((EXAMPLES / (scenario + ".json")).read_bytes())
    return path, digest(path.read_bytes())


def write(path, value):
    path.write_bytes(instrument.canonical(value))
    return digest(path.read_bytes())


def test_mixed_failure_error_keeps_full_global_verdict_under_filtering(tmp_path):
    path, sha = case(tmp_path)
    value = instrument.view(path, sha, status="passed")
    assert value["verdict"] == {
        "ok": False,
        "status": "failed",
        "summary": {"checks": 4, "passed": 2, "failed": 2},
    }
    assert value["matched_count"] == value["selected_count"] == 2
    assert all(c["status"] == "passed" for c in value["checks"])
    assert value["junit"] == {"tests": 4, "failures": 1, "errors": 1, "skipped": 0}
    assert value["evidence_origin"] == "test_double" and value["native_recomputation_recorded"]
    assert value["time_semantics"] == "sample_relative_no_verified_utc_origin"
    assert not value["source_files_rechecked"] and not value["hil_import_checks_reperformed"]
    assert not value["clock_alignment_verified"]
    assert all(value[k] is False for k in instrument.FLAGS)
    empty = instrument.view(path, sha, kind="uart", status="passed")
    assert empty["selected_count"] == 0 and not empty["verdict"]["ok"]


@pytest.mark.parametrize("version", ["0.9.0", "0.10.0"])
def test_old_and_current_hil_digital_producers_match_runtime_and_schema(tmp_path, version):
    import jsonschema

    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    bundle["producer_version"] = version
    schema = json.loads(
        (EXAMPLES.parents[1] / "schemas/instrument-report.schema.json").read_bytes()
    )
    jsonschema.validate(bundle, schema)
    assert instrument.view(path, write(path, bundle))["verdict"]["ok"] is False


def test_full_native_spans_and_invalid_signal_survive(tmp_path):
    path, sha = case(tmp_path)
    check = instrument.view(path, sha, check="console")["checks"][0]
    assert check["status"] == "invalid_evidence"
    assert check["assertions"][1]["status"] == "not_evaluated"
    pwm = instrument.view(path, sha, check="pwm")["checks"][0]
    assert pwm["status"] == "failed" and len(pwm["native"]["analysis"]["cycles"]) == 12
    assert pwm["native"]["analysis"]["cycles"][0]["raw_span"]["end_exclusive"] > 0
    assert pwm["native"]["raw_span_unit"] == "decoded_u16le_payload_bytes_end_exclusive"


def test_views_never_open_recorded_sources_or_start_processes(tmp_path, monkeypatch):
    path, sha = case(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("offline view touched network/process")

    original = instrument.read_file
    calls = []

    def once(selected, *args):
        assert selected == path and not calls
        calls.append(selected)
        raw, ref = original(selected, *args)
        selected.write_bytes(b"changed after snapshot")
        return raw, ref

    monkeypatch.setattr(instrument, "read_file", once)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = instrument.view(path, sha)
    assert len(calls) == 1 and result["selected_count"] == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("ok", True),
        ("ok", 0),
        ("status", "passed"),
        ("producer_version", "99.0.0"),
        ("native_exit_code", True),
        ("native_recomputation_recorded", False),
        ("validation_kind", "authenticated"),
        *[(key, True) for key in instrument.FLAGS],
    ],
)
def test_rehashed_bundle_edits_are_rejected(tmp_path, field, value):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    bundle[field] = value
    with pytest.raises(TraceError):
        instrument.view(path, write(path, bundle))


@pytest.mark.parametrize("role", list(instrument.LIMITS))
def test_embedded_byte_drift_is_rejected(tmp_path, role):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    item = bundle["inputs"][role]
    raw = base64.b64decode(item["raw_base64"]) + b" "
    item.update(raw_base64=base64.b64encode(raw).decode(), size_bytes=len(raw))
    with pytest.raises(TraceError):
        instrument.view(path, write(path, bundle))


@pytest.mark.parametrize("role", list(instrument.LIMITS))
def test_rehashing_changed_embedded_sources_does_not_rebind_native_result(tmp_path, role):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    item = bundle["inputs"][role]
    raw = base64.b64decode(item["raw_base64"]) + b" "
    item.update(raw_base64=base64.b64encode(raw).decode(), size_bytes=len(raw), sha256=digest(raw))
    with pytest.raises(TraceError):
        instrument.view(path, write(path, bundle))


@pytest.mark.parametrize(
    "filters",
    [
        {"offset": -1},
        {"offset": True},
        {"limit": 0},
        {"limit": 9},
        {"check": "absent"},
        {"kind": "unknown"},
        {"status": "unknown"},
    ],
)
def test_invalid_filters_fail_explicitly(tmp_path, filters):
    path, sha = case(tmp_path)
    with pytest.raises(TraceError):
        instrument.view(path, sha, **filters)


def test_cli_inspect_query_and_markdown_are_processing_success_not_test_success(tmp_path, capsys):
    path, sha = case(tmp_path)
    for operation in ("inspect", "query", "report"):
        output = tmp_path / "view.md"
        args = ["instrument", operation, str(path), "--sha256", sha, "--json"]
        if operation == "report":
            args += ["--output", str(output)]
        assert main(args) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["ok"] and result["data"]["verdict"]["ok"] is False
        assert result["data"]["verdict"]["summary"]["failed"] == 2
    text = output.read_text()
    assert '"status": "invalid_evidence"' in text and '"status": "failed"' in text
    assert '"native_recomputed_now": false' in text
    assert digest(output.read_bytes()) == result["data"]["output"]["sha256"]
    assert (
        main(args) == 2 and json.loads(capsys.readouterr().out)["error"]["code"] == "OUTPUT_EXISTS"
    )


def test_report_output_preflight_and_source_hash_errors(tmp_path, monkeypatch):
    path, sha = case(tmp_path)
    output = tmp_path / "view.md"
    output.write_bytes(b"preserve")

    def forbidden(*args, **kwargs):
        raise AssertionError("read before output preflight")

    monkeypatch.setattr(instrument, "read_file", forbidden)
    with pytest.raises(TraceError) as error:
        instrument.markdown(path, sha, output)
    assert error.value.code == "OUTPUT_EXISTS" and output.read_bytes() == b"preserve"


def test_wire_schema_and_embedded_sources_remain_unchanged(tmp_path):
    import jsonschema

    path, sha = case(tmp_path)
    before = path.read_bytes()
    bundle, _, _ = instrument.load(path, sha)
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas/instrument-report.schema.json").read_bytes()
    )
    jsonschema.validate(bundle, schema)
    instrument.view(path, sha, kind="pwm")
    assert path.read_bytes() == before
