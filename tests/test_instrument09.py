import base64
import json
from pathlib import Path

import pytest

from embedded_trace import instrument
from embedded_trace.common import TraceError, digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/instrument-09"


def case(tmp_path, scenario="passed"):
    path = tmp_path / "bundle.json"
    path.write_bytes((EXAMPLES / (scenario + ".json")).read_bytes())
    return path, digest(path.read_bytes())


@pytest.mark.parametrize("scenario", ["passed", "failed", "invalid", "mixed", "legacy"])
def test_current_verifier_evidence_keeps_complete_native_verdict(tmp_path, scenario):
    path, sha = case(tmp_path, scenario)
    value = instrument.view(path, sha, status="passed")
    assert value["verdict"]["ok"] is (scenario in ("passed", "legacy"))
    assert not value["native_recomputed_now"] and not value["hil_import_checks_reperformed"]
    if scenario == "mixed":
        assert not value["verdict"]["ok"] and value["junit"]["errors"] == 1
        assert value["junit"]["failures"] == 1 and value["selected_count"] > 0


@pytest.mark.parametrize("version", ["0.8.0", "0.7.0", "99.0.0", True, 0.9, None, []])
def test_rehashed_current_producer_with_invalid_verifier_pair_is_rejected(tmp_path, version):
    path, _ = case(tmp_path)
    bundle = json.loads(path.read_bytes())
    blob = bundle["inputs"]["native_result"]
    response = json.loads(base64.b64decode(blob["raw_base64"]))
    response["data"]["verification"]["verifier_version"] = version
    raw = instrument.canonical(response)
    blob.update(raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw), size_bytes=len(raw))
    manifest_blob = bundle["import_spec"]
    manifest = json.loads(base64.b64decode(manifest_blob["raw_base64"]))
    manifest["inputs"]["native_result"]["sha256"] = blob["sha256"]
    raw = instrument.canonical(manifest)
    manifest_blob.update(
        raw_base64=base64.b64encode(raw).decode(), sha256=digest(raw), size_bytes=len(raw)
    )
    raw = instrument.canonical(bundle)
    path.write_bytes(raw)
    with pytest.raises(TraceError, match="native verification"):
        instrument.view(path, digest(raw))
