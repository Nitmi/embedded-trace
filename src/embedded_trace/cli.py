from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .common import TraceError, json_bytes, write_new
from .query import inspect, query, validate
from .report import report
from .timeline import SAFETY, correlate


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Offline, hash-bound serial and RTT log timelines.")
    root.add_argument("--version", action="version", version=f"embedded-trace {__version__}")
    commands = root.add_subparsers(dest="operation", required=True)
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
