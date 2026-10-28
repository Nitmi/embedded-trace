"""Installed Trace views; retains global failures under empty/passing filters."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


def verify(run, cli, root):
    archive = Path(__file__).resolve().parents[1] / "examples/thermal/fixtures.zip"
    with ZipFile(archive) as z:
        for info in z.infolist():
            assert info.file_size <= 32 * 1024 * 1024
            name = Path(info.filename).stem
            path = root / ("thermal-" + info.filename)
            path.write_bytes(z.read(info))
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            for op in ("inspect", "query", "report"):
                args = [*cli, "thermal", op, str(path), "--sha256", sha, "--json"]
                if op == "query":
                    args += ["--status", "passed"]
                if op == "report":
                    args += ["--output", str(root / ("thermal-" + name + ".md"))]
                value = json.loads(run("thermal-" + name + "-" + op, args))
                assert value["ok"] and value["data"]["verdict"]["ok"] is (name == "passed")
                assert not value["data"]["hil_import_checks_reperformed"]
                assert not value["native_temperature_conversion_performed"]
            value = json.loads(
                run(
                    "thermal-" + name + "-empty",
                    [
                        *cli,
                        "thermal",
                        "query",
                        str(path),
                        "--sha256",
                        sha,
                        "--offset",
                        "8",
                        "--json",
                    ],
                )
            )
            assert value["data"]["selected_checks"] == 0
            assert value["data"]["verdict"]["ok"] is (name == "passed")
    return True
