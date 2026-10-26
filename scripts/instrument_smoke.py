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
    examples = Path(__file__).resolve().parents[1] / "examples/instrument-09"
    for scenario in ("passed", "failed", "invalid", "mixed", "legacy"):
        path = root / ("digital09-" + scenario + ".json")
        path.write_bytes((examples / (scenario + ".json")).read_bytes())
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        for operation in ("inspect", "query", "report"):
            args = [*cli, "instrument", operation, str(path), "--sha256", sha, "--json"]
            if operation == "query":
                args += ["--status", "passed"]
            if operation == "report":
                args += ["--output", str(root / ("digital09-" + scenario + ".md"))]
            response = json.loads(run("digital09-" + scenario + "-" + operation, args))
            assert response["ok"] and response["data"]["verdict"]["ok"] is (
                scenario in ("passed", "legacy")
            )
    examples = Path(__file__).resolve().parents[1] / "examples/waveform"
    for scenario in ("passed", "failed", "invalid", "mixed", "sds"):
        path = root / ("waveform-" + scenario + ".json")
        path.write_bytes((examples / (scenario + ".json")).read_bytes())
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        for operation in ("inspect", "query", "report"):
            args = [*cli, "waveform", operation, str(path), "--sha256", sha, "--json"]
            if operation == "query":
                args += ["--status", "passed"]
            if operation == "report":
                args += ["--output", str(root / ("waveform-" + scenario + ".md"))]
            response = json.loads(run("waveform-" + scenario + "-" + operation, args))
            assert response["ok"] and response["data"]["verdict"]["ok"] is (
                scenario in ("passed", "sds")
            )
            assert not response["native_recomputed_now"] and not response["hardware_access"]
            assert response["data"]["source"]["evidence_origin"] == "test_double"
    for domain, directory, scenarios in (
        ("load", "load", ("passed", "failed", "invalid", "mixed", "cleanup", "timeout")),
        ("instrument", "instrument-10", ("passed", "failed", "invalid", "mixed", "legacy")),
        ("waveform", "waveform-10", ("passed", "failed", "invalid")),
    ):
        for scenario in scenarios:
            path = root / (directory + "-" + scenario + ".json")
            path.write_bytes(
                (
                    Path(__file__).resolve().parents[1]
                    / "examples"
                    / directory
                    / (scenario + ".json")
                ).read_bytes()
            )
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            for operation in ("inspect", "query", "report"):
                args = [*cli, domain, operation, str(path), "--sha256", sha, "--json"]
                if operation == "query":
                    args += ["--status", "passed"]
                if operation == "report":
                    args += ["--output", str(root / (directory + "-" + scenario + ".md"))]
                response = json.loads(run(directory + "-" + scenario + "-" + operation, args))
                assert response["ok"] and response["data"]["verdict"]["ok"] is (
                    scenario in ("passed", "legacy")
                )
                assert not response["hardware_access"] and not response["native_recomputed_now"]
                source = response["data"] if domain == "instrument" else response["data"]["source"]
                assert source["evidence_origin"] == "test_double"
    return True
