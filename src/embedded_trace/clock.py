from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from .common import TraceError, require, text

STAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


def unix_ns(value: Any) -> int:
    value = text(value, "timestamp", 40)
    match = STAMP.fullmatch(value)
    require(match is not None, "timestamp must be timezone-qualified RFC3339")
    try:
        stamp = datetime.fromisoformat(match[1] + "T" + match[2])
        zone = match[4]
        offset = 0
        if zone != "Z":
            hours, minutes = map(int, zone[1:].split(":"))
            require(hours <= 23 and minutes <= 59, "invalid timezone offset")
            require(zone != "-00:00", "unknown timezone offset is not a clock")
            offset = (hours * 60 + minutes) * (1 if zone[0] == "+" else -1)
        delta = stamp - timedelta(minutes=offset) - datetime(1970, 1, 1)
    except (ValueError, OverflowError) as error:
        if isinstance(error, TraceError):
            raise
        raise TraceError("INVALID_INPUT", "invalid calendar timestamp") from error
    result = (delta.days * 86400 + delta.seconds) * 10**9 + int((match[3] or "").ljust(9, "0"))
    require(0 <= result < 253402300800 * 10**9, "timestamp outside supported epoch range")
    return result


def observed(first: dict, last: dict) -> dict:
    return {
        "first_recorded_at": first["timestamp"],
        "last_recorded_at": last["timestamp"],
        "minimum_unix_ns": str(min(first["ns"], last["ns"])),
        "maximum_unix_ns": str(max(first["ns"], last["ns"])),
    }
