from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FLASH_SOURCE_BYTES = 12 * 1024 * 1024
MAX_SIM_TOTAL_BYTES = 96 * 1024 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 128 * 1024
MAX_RECORDS = 20000
MAX_EVENTS = 20000
MAX_LINE_BYTES = 65536
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


class TraceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def require(condition: bool, message: str, code: str = "INVALID_INPUT") -> None:
    if not condition:
        raise TraceError(code, message)


def integer(value: Any, name: str, minimum: int = 0, maximum: int = 2**64 - 1) -> int:
    require(type(value) is int and minimum <= value <= maximum, f"invalid {name}")
    return value


def text(value: Any, name: str, maximum: int = 512) -> str:
    require(isinstance(value, str) and len(value) <= maximum, f"invalid {name}")
    # Reject unpaired surrogates, including ones introduced by JSON escape sequences.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise TraceError("INVALID_INPUT", f"invalid Unicode in {name}") from error
    return value


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _float(value: str) -> float:
    result = float(value)
    require(math.isfinite(result), "nonfinite JSON number")
    return result


def _constant(value: str) -> None:
    raise TraceError("INVALID_INPUT", f"nonfinite JSON number: {value}")


def parse_json(raw: bytes) -> dict:
    try:
        result = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_float,
            parse_constant=_constant,
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, TraceError):
            raise
        raise TraceError("INVALID_INPUT", "invalid UTF-8 JSON") from error
    require(isinstance(result, dict), "JSON root must be an object")
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 32, "JSON exceeds depth limit")
        if isinstance(value, dict):
            for key, child in value.items():
                text(key, "JSON field", MAX_RECORD_BYTES)
                pending.append((child, depth + 1))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            text(value, "JSON string", MAX_DOCUMENT_BYTES)
    return result


def checked_path(path: Path) -> Path:
    """Reject links/reparse points and special files without opening them."""
    absolute = Path(os.path.abspath(path))
    require(
        not str(absolute).startswith(("\\\\", "//")), "network and device paths are not supported"
    )
    for part in (*reversed(absolute.parents), absolute):
        info = part.lstat()
        require(
            not stat.S_ISLNK(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400),
            "links and reparse points are not supported",
        )
    return absolute


def read_file(path: Path, maximum: int, expected: str | None = None) -> tuple[bytes, dict]:
    path = checked_path(path)
    require(stat.S_ISREG(path.stat().st_mode), "input must be a regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode), "input is not a regular file")
        limit = maximum + 1
        # Use size only to avoid allocating the whole limit for a small file.
        # Probe beyond it: the opened file may have grown or returned a short read.
        raw = stream.read(min(limit, opened.st_size + 1))
        if len(raw) < limit:
            tail = stream.read(1)
            if tail:
                chunks = [raw, tail]
                size = len(raw) + len(tail)
                while size < limit:
                    chunk = stream.read(min(65536, limit - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                raw = b"".join(chunks)
    require(len(raw) <= maximum, "input exceeds byte limit", "LIMIT_EXCEEDED")
    actual = digest(raw)
    if expected is not None:
        require(
            isinstance(expected, str) and SHA.fullmatch(expected) is not None, "invalid SHA-256"
        )
        require(actual == expected, "input SHA-256 differs", "HASH_MISMATCH")
    return raw, {"path": str(path), "sha256": actual, "size_bytes": len(raw)}


def relative_source(base: Path, value: Any) -> Path:
    value = text(value, "source path", 1024)
    require(bool(value) and "\\" not in value and ":" not in value, "invalid source path")
    parts = value.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        prefix + str(index) for prefix in ("COM", "LPT") for index in range(1, 10)
    }
    for part in parts:
        require(
            part not in ("", ".", "..")
            and not part.endswith((" ", "."))
            and not any(ord(char) < 32 or char in '<>"|?*' for char in part)
            and part.split(".")[0].upper() not in reserved,
            "source path must be a portable relative path without traversal",
        )
    return base.joinpath(*parts)


def json_bytes(value: dict) -> bytes:
    raw = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    ).encode()
    require(len(raw) <= MAX_DOCUMENT_BYTES, "output exceeds byte limit", "LIMIT_EXCEEDED")
    return raw


def write_new(path: Path, value: dict) -> dict:
    return write_new_bytes(path, json_bytes(value))


def write_new_bytes(path: Path, raw: bytes, maximum: int = MAX_DOCUMENT_BYTES) -> dict:
    require(len(raw) <= maximum, "output exceeds byte limit", "LIMIT_EXCEEDED")
    parent = checked_path(path.parent)
    require(parent.is_dir(), "output parent must be a directory")
    destination = relative_source(parent, path.name)
    require(
        not destination.exists() and not destination.is_symlink(), "output exists", "OUTPUT_EXISTS"
    )
    try:
        with destination.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise TraceError("OUTPUT_EXISTS", "output exists") from error
    return {"path": str(destination), "sha256": digest(raw), "size_bytes": len(raw)}
