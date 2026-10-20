from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import jsonschema
import pytest

from embedded_trace.cli import main
from embedded_trace.common import TraceError
from embedded_trace.query import validate
from embedded_trace.timeline import correlate

ROOT = Path(__file__).resolve().parents[1]


def test_all_published_schemas_and_synthetic_example(tmp_path, capsys):
    for path in (ROOT / "schemas").glob("*.json"):
        jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))
    spec = ROOT / "examples/synthetic/input.json"
    input_schema = json.loads((ROOT / "schemas/input.v1.schema.json").read_text())
    jsonschema.validate(json.loads(spec.read_text()), input_schema)
    output = tmp_path / "timeline.json"
    assert main(["correlate", str(spec), "--output", str(output), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    schema = json.loads((ROOT / "schemas/result.v1.schema.json").read_text())
    jsonschema.validate(value, schema)
    document = json.loads(output.read_text())
    jsonschema.validate(
        document, json.loads((ROOT / "schemas/timeline.v1.schema.json").read_text())
    )
    validate(document)
    assert main(["correlate", str(spec), "--output", str(output), "--json"]) == 2
    jsonschema.validate(json.loads(capsys.readouterr().out), schema)


@pytest.mark.parametrize("mode", ["serial", "rtt"])
def test_every_two_chunk_partition_preserves_bytes_and_spans(case, mode):
    payload = "ab中\r\n\nlast".encode()
    expected = ["ab中\r\n".encode(), b"\n", b"last"]
    for split in range(1, len(payload)):
        chunks = [payload[:split], payload[split:]]
        spec = case(chunks if mode == "serial" else None, chunks if mode == "rtt" else None)
        document = correlate(spec)
        validate(document)
        events = sorted(
            (event for event in document["events"] if event["kind"] == "line"),
            key=lambda event: event["source_ordinal"],
        )
        assert [base64.b64decode(event["payload"]["raw_base64"]) for event in events] == expected
        offset = 2 if mode == "serial" else 3
        for event in events:
            recovered = b"".join(
                chunks[span["record_index"] - offset][
                    span["payload_byte_start"] : span["payload_byte_end"]
                ]
                for span in event["payload"]["segments"]
            )
            assert recovered == base64.b64decode(event["payload"]["raw_base64"])


@pytest.mark.parametrize(
    "mutation", ["integrity", "elapsed", "cursor", "coverage", "total", "source-index"]
)
def test_internal_inventory_must_remain_consistent(case, mutation):
    document = copy.deepcopy(correlate(case([b"A\n"])))
    source = document["sources"][0]
    event = next(row for row in document["events"] if row["kind"] == "line")
    if mutation == "integrity":
        source["integrity"] = {}
    elif mutation == "elapsed":
        event["elapsed_ms"] = {}
    elif mutation == "cursor":
        event["payload"]["segments"][0]["stream_byte_start"] = 1
        event["payload"]["segments"][0]["stream_byte_end"] += 1
    elif mutation == "coverage":
        source["record_count"] += 1
    elif mutation == "total":
        source["payload_bytes"] += 1
    else:
        source["source_index"] = False
    with pytest.raises(TraceError):
        validate(document)
