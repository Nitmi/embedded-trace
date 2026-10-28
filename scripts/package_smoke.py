"""Development-only installed-wheel checks. Does not access hardware."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from instrument_smoke import verify as verify_instruments


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    wheels = list(args.dist_dir.glob("*.whl"))
    assert len(wheels) == 1, "expected one built wheel"
    wheel = wheels[0].resolve()
    project_root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((project_root / "pyproject.toml").read_text())["project"]["version"]
    root = args.output_dir.absolute()
    root.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    commands = []

    def run(label, command, expected=0):
        completed = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            check=False,
            cwd=root,
            env=environment,
            timeout=60,
        )
        (root / (label + ".stdout")).write_text(completed.stdout, encoding="utf-8")
        (root / (label + ".stderr")).write_text(completed.stderr, encoding="utf-8")
        commands.append(
            {
                "label": label,
                "argv": [str(part) for part in command],
                "exit_code": completed.returncode,
                "expected_exit_code": expected,
            }
        )
        assert completed.returncode == expected, (label, completed.stderr, completed.stdout)
        return completed.stdout

    uv = shutil.which("uv")
    assert uv, "uv is required for this development helper"
    venv = root / "venv"
    run("venv", [uv, "venv", "--python", sys.executable, str(venv)])
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    launcher = venv / ("Scripts/embedded-trace.exe" if os.name == "nt" else "bin/embedded-trace")
    run(
        "install",
        [uv, "pip", "install", "--python", str(python), "--no-index", "--no-deps", str(wheel)],
    )
    identity = json.loads(
        run(
            "identity",
            [
                str(python),
                "-I",
                "-c",
                "import embedded_trace,json,sys;"
                "print(json.dumps({'version':embedded_trace.__version__,"
                "'path':embedded_trace.__file__,'python':sys.version}))",
            ],
        )
    )
    assert identity["version"] == version and Path(identity["path"]).is_relative_to(venv)
    assert (
        run("launcher-version", [str(launcher), "--version"]).strip() == f"embedded-trace {version}"
    )
    run("help", [str(python), "-I", "-m", "embedded_trace", "--help"])
    fixture = project_root / "examples/synthetic"
    inputs = root / "inputs"
    shutil.copytree(fixture, inputs)
    timeline = root / "timeline.json"
    cli = [str(python), "-I", "-m", "embedded_trace"]
    correlated = json.loads(
        run(
            "correlate",
            [*cli, "correlate", str(inputs / "input.json"), "--output", str(timeline), "--json"],
        )
    )
    sha = correlated["data"]["output"]["sha256"]
    original = timeline.read_bytes()
    assert hashlib.sha256(original).hexdigest() == sha
    inspected = json.loads(
        run("inspect", [*cli, "inspect", str(timeline), "--sha256", sha, "--json"])
    )
    assert inspected["data"]["capture_outcomes"] == {"uart": "succeeded", "rtt": "succeeded"}
    found = json.loads(
        run(
            "query",
            [*cli, "query", str(timeline), "--sha256", sha, "--contains", "READY", "--json"],
        )
    )
    assert found["data"]["matches_total"] == 1
    row = found["data"]["events"][0]
    assert row["record_start"] == 2 and row["record_end"] == 3 and row["payload"]["text"] == "READY"
    overlapped = json.loads(
        run(
            "interval",
            [
                *cli,
                "query",
                str(timeline),
                "--sha256",
                sha,
                "--contains",
                "READY",
                "--since",
                "2026-01-01T00:00:00.002Z",
                "--until",
                "2026-01-01T00:00:00.002Z",
                "--json",
            ],
        )
    )
    assert overlapped["data"]["matches_total"] == 1
    rejected = json.loads(
        run("wrong-hash", [*cli, "query", str(timeline), "--sha256", "0" * 64, "--json"], 2)
    )
    assert rejected["error"]["code"] == "HASH_MISMATCH"
    refused = json.loads(
        run(
            "overwrite",
            [*cli, "correlate", str(inputs / "input.json"), "--output", str(timeline), "--json"],
            2,
        )
    )
    assert refused["error"]["code"] == "OUTPUT_EXISTS" and timeline.read_bytes() == original
    source = inputs / "serial.jsonl"
    source.write_bytes(source.read_bytes() + b" ")
    markdown = root / "report.md"
    rendered = json.loads(
        run(
            "report",
            [
                *cli,
                "report",
                str(timeline),
                "--sha256",
                sha,
                "--contains",
                "READY",
                "--output",
                str(markdown),
                "--json",
            ],
        )
    )
    assert rendered["data"]["selected_count"] == 1
    assert rendered["data"]["source_files_rechecked"] is False
    assert hashlib.sha256(markdown.read_bytes()).hexdigest() == rendered["data"]["output"]["sha256"]
    assert '"text_preview": "READY"' in markdown.read_text()
    report_error = json.loads(
        run(
            "report-overwrite",
            [
                *cli,
                "report",
                str(timeline),
                "--sha256",
                sha,
                "--output",
                str(markdown),
                "--json",
            ],
            2,
        )
    )
    assert report_error["error"]["code"] == "OUTPUT_EXISTS"
    drift = root / "never-created.json"
    error = json.loads(
        run(
            "drift",
            [*cli, "correlate", str(inputs / "input.json"), "--output", str(drift), "--json"],
            2,
        )
    )
    assert error["error"]["code"] == "HASH_MISMATCH" and not drift.exists()
    assert verify_instruments(run, cli, root)
    from thermal_smoke import verify as verify_thermal

    assert verify_thermal(run, cli, root)
    package = Path(identity["path"]).parent
    verified = 0
    with zipfile.ZipFile(wheel) as archive:
        for item in archive.infolist():
            if item.filename.startswith("embedded_trace/") and not item.is_dir():
                assert (package.parent / item.filename).read_bytes() == archive.read(item)
                verified += 1
    assert verified == 24  # Seventeen modules and seven schemas; no runtime dependency.
    for value in (correlated, inspected, found, overlapped, rendered):
        assert value["hardware_access"] is False and value["executables_started"] is False
        assert value["cross_source_clock_alignment_verified"] is False
    result = {
        "ok": True,
        "wheel": str(wheel),
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "identity": identity,
        "package_files_verified": verified,
        "instrument_views_verified": True,
        "commands": commands,
        "hardware_access": False,
    }
    (root / "package-smoke.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "commands": len(commands),
                "package_files_verified": verified,
                "output": str(root / "package-smoke.json"),
                "hardware_access": False,
            }
        )
    )


if __name__ == "__main__":
    main()
