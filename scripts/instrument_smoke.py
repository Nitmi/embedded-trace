"""Installed artifact views using generated, explicitly synthetic evidence."""

import hashlib
import json
from pathlib import Path


def verify(run, cli, root):
    examples = Path(__file__).resolve().parents[1] / "examples/instrument"
    for scenario in ("passed", "mixed"):
        path = root / ("instrument-" + scenario + ".json")
        path.write_bytes((examples / (scenario + ".json")).read_bytes())
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        for operation in ("inspect", "query", "report"):
            args = [*cli, "instrument", operation, str(path), "--sha256", sha, "--json"]
            if operation == "query":
                args += ["--kind", "pwm"]
            if operation == "report":
                output = root / ("instrument-" + scenario + ".md")
                args += ["--output", str(output)]
            response = json.loads(run("instrument-" + scenario + "-" + operation, args))
            assert response["ok"] and response["data"]["verdict"]["ok"] is (scenario == "passed")
            assert response["data"]["evidence_origin"] == "test_double"
            assert not response["hardware_access"] and not response["native_recomputed_now"]
            if operation == "report":
                assert (
                    response["data"]["output"]["sha256"]
                    == hashlib.sha256(output.read_bytes()).hexdigest()
                )
        bad = [*cli, "instrument", "inspect", str(path), "--sha256", "0" * 64, "--json"]
        assert (
            json.loads(run("instrument-" + scenario + "-bad-hash", bad, 2))["error"]["code"]
            == "HASH_MISMATCH"
        )
    return True
