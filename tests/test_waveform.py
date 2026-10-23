import base64
import json
import socket
import subprocess
from pathlib import Path

import pytest

from embedded_trace import waveform
from embedded_trace.cli import main
from embedded_trace.common import TraceError, digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/waveform"


def case(tmp_path, scenario="mixed"):
    path = tmp_path / "bundle.json"
    path.write_bytes((EXAMPLES / (scenario + ".json")).read_bytes())
    return path, digest(path.read_bytes())


def write(path, value):
    path.write_bytes(waveform.canonical(value))
    return digest(path.read_bytes())


@pytest.mark.parametrize("scenario", ["passed", "failed", "invalid", "mixed", "sds"])
def test_native_evidence_qualifications_metrics_and_spans_preserved(tmp_path, scenario):
    path, sha = case(tmp_path, scenario)
    view = waveform.view(path, sha)
    assert view["source"]["evidence_origin"] == "test_double"
    assert view["verdict"]["ok"] is (scenario in ("passed", "sds"))
    assert view["native_recomputation_recorded"]
    assert all(view[k] is False for k in waveform.FLAGS)
    assert not view["hil_import_checks_reperformed"] and not view["clock_alignment_verified"]
    if scenario != "invalid":
        check = view["checks"][0]
        assert check["raw_span"]["end_exclusive"] > check["raw_span"]["start"]
        assert set(check["metrics"]) == {
            "minimum_v",
            "maximum_v",
            "mean_v",
            "peak_to_peak_v",
            "rms_v",
            "ac_rms_v",
        }
    if scenario == "sds":
        assert (
            view["source"]["source_freshness"]["basis"] == "existing_stopped_waveform_age_unknown"
        )
        assert view["checks"][0]["source_samples"]["descriptor"]["probe_factor"] == 10.0


def test_filters_and_empty_page_keep_full_failure_and_error_verdict(tmp_path):
    path, sha = case(tmp_path)
    for filters, count in [
        ({"status": "passed"}, 1),
        ({"check": "absent"}, 0),
        ({"offset": 8}, 0),
        ({"channel": 4}, 0),
    ]:
        view = waveform.view(path, sha, **filters)
        assert view["verdict"] == {
            "ok": False,
            "status": "failed",
            "summary": {"checks": 3, "passed": 1, "failed": 1, "invalid_evidence": 1},
        }
        assert view["selected_checks"] == count
        assert view["junit"] == dict(tests=3, failures=1, errors=1, skipped=0)


def test_only_bundle_opened_once_and_no_network_or_process(tmp_path, monkeypatch):
    path, sha = case(tmp_path, "sds")
    original = waveform.read_file
    calls = []

    def once(selected, *args):
        assert selected == path and not calls
        calls.append(selected)
        raw, ref = original(selected, *args)
        selected.write_bytes(b"changed after snapshot")
        return raw, ref

    def forbidden(*args, **kwargs):
        pytest.fail("offline view touched network/process")

    monkeypatch.setattr(waveform, "read_file", once)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert waveform.view(path, sha)["verdict"]["ok"] and len(calls) == 1


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
        *[(key, True) for key in waveform.FLAGS],
    ],
)
def test_rehashed_bundle_claims_and_projections_rejected(tmp_path, field, value):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    bundle[field] = value
    with pytest.raises(TraceError):
        waveform.view(path, write(path, bundle))


@pytest.mark.parametrize("role", list(waveform.LIMITS))
@pytest.mark.parametrize("rehash", [False, True])
def test_embedded_byte_drift_and_rehash_cannot_rebind_report(tmp_path, role, rehash):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    blob = bundle["inputs"][role]
    raw = base64.b64decode(blob["raw_base64"]) + b" "
    blob.update(raw_base64=base64.b64encode(raw).decode(), size_bytes=len(raw))
    if rehash:
        blob["sha256"] = digest(raw)
    with pytest.raises(TraceError):
        waveform.view(path, write(path, bundle))


@pytest.mark.parametrize("mutation", ["missing", "hash", "empty", "large", "duplicate"])
def test_sds_original_inventory_not_silently_stripped(tmp_path, mutation):
    path, _ = case(tmp_path, "sds")
    bundle = json.loads(path.read_bytes())
    name = next(iter(bundle["source_files"]))
    if mutation == "missing":
        del bundle["source_files"][name]
    elif mutation == "hash":
        bundle["source_files"][name]["sha256"] = "0" * 64
    elif mutation == "empty":
        blob = bundle["source_files"][name]
        blob.update(size_bytes=0, sha256=digest(b""), raw_base64="")
    elif mutation == "large":
        bundle["source_files"][name]["size_bytes"] = 1048577
    else:
        bundle["source_files"][name + ".copy"] = bundle["source_files"][name]
    with pytest.raises(TraceError):
        waveform.view(path, write(path, bundle))


@pytest.mark.parametrize(
    "filters",
    [
        {"offset": True},
        {"offset": -1},
        {"limit": 9},
        {"limit": 0},
        {"channel": 0},
        {"channel": True},
        {"status": "unknown"},
        {"check": "x" * 65},
    ],
)
def test_invalid_filter_is_error(tmp_path, filters):
    path, sha = case(tmp_path)
    with pytest.raises(TraceError):
        waveform.view(path, sha, **filters)


def test_cli_complete_failed_verdict_and_inert_bounded_markdown(tmp_path, capsys):
    path, sha = case(tmp_path)
    for operation in ("inspect", "query", "report"):
        args = ["waveform", operation, str(path), "--sha256", sha, "--json"]
        output = tmp_path / "waveform.md"
        if operation == "report":
            args += ["--output", str(output), "--status", "passed"]
        assert main(args) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["ok"] and not result["data"]["verdict"]["ok"]
    text = output.read_text()
    assert "Global verdict: failed" in text and '"calibration_verified": false' in text
    assert result["data"]["output"]["sha256"] == digest(output.read_bytes())
    assert main(args) == 2
    assert not json.loads(capsys.readouterr().out)["ok"]


def test_bad_hash_duplicate_json_and_document_limit(tmp_path):
    path, sha = case(tmp_path)
    with pytest.raises(TraceError, match="SHA-256"):
        waveform.view(path, "0" * 64)
    raw = path.read_bytes().replace(b'"schema_version":', b'"ok":true,"schema_version":', 1)
    path.write_bytes(raw)
    with pytest.raises(TraceError, match="duplicate"):
        waveform.view(path, digest(raw))
    with pytest.raises(TraceError):
        waveform.canonical({"large": "x" * waveform.MAX_BUNDLE})
