from __future__ import annotations

import base64

from .clock import observed
from .common import MAX_EVENTS, MAX_LINE_BYTES, digest, require


class Framer:
    def __init__(self, source: dict, events: list[dict]):
        self.source = source
        self.events = events
        self.streams: dict[str, dict] = {}

    def add(self, event: dict) -> None:
        require(len(self.events) < MAX_EVENTS, "too many normalized events", "LIMIT_EXCEEDED")
        self.source["event_count"] += 1
        self.events.append(
            {
                "id": f"{self.source['id']}:{self.source['event_count']}",
                "source_id": self.source["id"],
                "source_ordinal": self.source["event_count"],
                "clock_domain": self.source["clock_domain"],
                **event,
            }
        )

    def metadata(self, record: dict, context: dict) -> None:
        self.add(
            {
                "kind": "native",
                "record_start": context["index"],
                "record_end": context["index"],
                "time": observed(context, context),
                "native": record,
            }
        )

    def feed(self, stream: str, step: str, payload: bytes, context: dict, atomic: bool = False):
        state = self.streams.setdefault(
            stream,
            {
                "buffer": bytearray(),
                "segments": [],
                "contexts": [],
                "cursor": 0,
                "step": step,
            },
        )
        if state["step"] != step:
            self.flush(stream, "step_change")
            state["step"] = step
        start = 0
        while start < len(payload):
            newline = payload.find(b"\n", start)
            end = newline + 1 if newline >= 0 else len(payload)
            require(
                len(state["buffer"]) + end - start <= MAX_LINE_BYTES,
                "line exceeds byte limit",
                "LIMIT_EXCEEDED",
            )
            state["buffer"].extend(payload[start:end])
            state["segments"].append(
                {
                    "record_index": context["index"],
                    "payload_byte_start": start,
                    "payload_byte_end": end,
                    "stream_byte_start": state["cursor"],
                    "stream_byte_end": state["cursor"] + end - start,
                }
            )
            state["contexts"].append(context)
            state["cursor"] += end - start
            start = end
            if newline >= 0:
                self.flush(stream, "newline")
        if atomic:
            self.flush(stream, "record_end")

    def flush(self, stream: str, boundary: str) -> None:
        state = self.streams[stream]
        if not state["buffer"]:
            return
        payload = bytes(state["buffer"])
        terminator = (
            "crlf" if payload.endswith(b"\r\n") else "lf" if payload.endswith(b"\n") else None
        )
        content = (
            payload[: -len({"crlf": b"\r\n", "lf": b"\n"}[terminator])] if terminator else payload
        )
        try:
            decoded = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            decoded = None
        contexts = state["contexts"]
        first, last = contexts[0], contexts[-1]
        times = [context["ns"] for context in contexts]
        timing = observed(first, last)
        timing.update(minimum_unix_ns=str(min(times)), maximum_unix_ns=str(max(times)))
        self.add(
            {
                "kind": "line",
                "stream": stream,
                "step": state["step"],
                "record_start": first["index"],
                "record_end": last["index"],
                "time": timing,
                "elapsed_ms": {"first": first.get("elapsed_ms"), "last": last.get("elapsed_ms")},
                "payload": {
                    "raw_base64": base64.b64encode(payload).decode("ascii"),
                    "length": len(payload),
                    "sha256": digest(payload),
                    "text": decoded,
                    "utf8_valid": decoded is not None,
                    "terminator": terminator,
                    "complete": terminator is not None,
                    "boundary": boundary,
                    "segments": list(state["segments"]),
                },
            }
        )
        if terminator is None:
            warnings = self.source["warnings"]
            warnings["unterminated_lines"] = warnings.get("unterminated_lines", 0) + 1
        state["buffer"].clear()
        state["segments"].clear()
        state["contexts"].clear()

    def finish(self) -> None:
        for stream in self.streams:
            self.flush(stream, "end_of_input")
