from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, instrument
from .common import TraceError, json_bytes, write_new
from .query import inspect, query, validate
from .report import report
from .timeline import SAFETY, correlate


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Offline, hash-bound serial, RTT and simulation timelines."
    )
    root.add_argument("--version", action="version", version=f"embedded-trace {__version__}")
    commands = root.add_subparsers(dest="operation", required=True)
    instruments = commands.add_parser("instrument", help="offline HIL instrument evidence views")
    views = instruments.add_subparsers(dest="instrument_operation", required=True)
    for name in ("inspect", "query", "report"):
        item = views.add_parser(name)
        item.add_argument("input", type=Path)
        item.add_argument("--sha256", required=True)
        item.add_argument("--json", action="store_true")
        if name != "inspect":
            item.add_argument("--check")
            item.add_argument("--kind", choices=("uart", "pwm", "i2c", "spi"))
            item.add_argument("--status", choices=("passed", "failed", "invalid_evidence"))
            item.add_argument("--offset", type=int, default=0)
            item.add_argument("--limit", type=int, default=8)
        if name == "report":
            item.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("correlate", help="correlate explicitly selected saved logs")
    build.add_argument("input", type=Path)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--json", action="store_true")
    for name in ("inspect", "query", "report"):
        item = commands.add_parser(name)
        item.add_argument("input", type=Path)
        item.add_argument("--sha256", required=True)
        item.add_argument("--json", action="store_true")
        if name == "report":
            item.add_argument("--output", type=Path, required=True)
        if name in ("query", "report"):
            item.add_argument("--contains")
            item.add_argument("--source")
            item.add_argument("--clock-domain", dest="domain")
            item.add_argument("--since")
            item.add_argument("--until")
            item.add_argument("--offset", type=int, default=0)
            item.add_argument("--limit", type=int, default=20)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.operation == "instrument":
        result = {
            "schema_version": "embedded-trace.instrument-result.v1",
            "operation": "instrument." + args.instrument_operation,
            "scope": "host_only_saved_instrument_view",
            **instrument.FLAGS,
        }
        try:
            filters = (
                {}
                if args.instrument_operation == "inspect"
                else {
                    key: getattr(args, key)
                    for key in ("check", "kind", "status", "offset", "limit")
                }
            )
            data = (
                instrument.markdown(args.input, args.sha256, args.output, **filters)
                if args.instrument_operation == "report"
                else instrument.view(args.input, args.sha256, **filters)
            )
            if args.instrument_operation == "inspect":
                data["checks"] = [
                    {k: c[k] for k in ("id", "kind", "status", "native_sha256")}
                    for c in data["checks"]
                ]
            result.update(ok=True, data=data)
            code = 0
        except (TraceError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            result.update(
                ok=False,
                error={
                    "code": getattr(error, "code", "INVALID_INPUT"),
                    "message": str(error)[:1024],
                },
            )
            code = 2
        sys.stdout.write(instrument.canonical(result).decode("ascii"))
        return code
    result = {
        "schema_version": "embedded-trace.result.v1",
        "operation": "trace." + args.operation,
        "scope": "host_only_saved_log_correlation",
        **SAFETY,
    }
    try:
        if args.operation == "correlate":
            document = correlate(args.input)
            validate(document)
            output = write_new(args.output, document)
            data = {
                "output": output,
                "status": document["status"],
                "source_count": len(document["sources"]),
                "event_count": document["event_count"],
            }
        elif args.operation == "inspect":
            data = inspect(args.input, args.sha256)
        else:
            operation = report if args.operation == "report" else query
            data = operation(
                args.input,
                args.sha256,
                **({"output": args.output} if args.operation == "report" else {}),
                **{
                    key: getattr(args, key)
                    for key in ("contains", "source", "domain", "since", "until", "offset", "limit")
                },
            )
        result.update(ok=True, data=data)
        code = 0
    except TraceError as error:
        result.update(ok=False, error={"code": error.code, "message": str(error)})
        code = 2
    except OSError as error:
        result.update(ok=False, error={"code": "HOST_IO_ERROR", "message": str(error)})
        code = 4
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError) as error:
        result.update(
            ok=False, error={"code": "INVALID_INPUT", "message": str(error) or type(error).__name__}
        )
        code = 2
    try:
        encoded = json_bytes(result)
    except TraceError as error:
        result = {key: value for key, value in result.items() if key not in ("data", "error")}
        result.update(ok=False, error={"code": error.code, "message": str(error)})
        encoded = json_bytes(result)
        code = 2
    sys.stdout.write(encoded.decode("ascii"))
    return code
