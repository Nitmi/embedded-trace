from __future__ import annotations

import stat
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest

from embedded_trace import common
from embedded_trace.common import MAX_DOCUMENT_BYTES, TraceError, digest, read_file


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x00\xff\r\n1234"])
def test_exact_limit_preserves_bytes_and_receipt(tmp_path, payload):
    path = tmp_path / "evidence.bin"
    path.write_bytes(payload)
    raw, receipt = read_file(path, len(payload), digest(payload))
    assert raw == payload
    assert receipt == {
        "path": str(path.absolute()),
        "sha256": digest(payload),
        "size_bytes": len(payload),
    }


@pytest.mark.parametrize("hint", [0, 1, 7, 8, 9, MAX_DOCUMENT_BYTES])
@pytest.mark.parametrize("short_read", [None, 1, 3])
@pytest.mark.parametrize("overflow", [False, True])
def test_size_hint_and_short_reads_never_truncate_or_bypass_limit(
    tmp_path, monkeypatch, hint, short_read, overflow
):
    path = tmp_path / "changing.bin"
    payload = b"12345678" + (b"!" if overflow else b"")
    path.write_bytes(payload)
    original_open = Path.open
    bytes_read = []

    class Reader:
        def __init__(self):
            self.stream = original_open(path, "rb")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, count):
            assert 0 < count <= 9
            raw = self.stream.read(min(count, short_read) if short_read else count)
            bytes_read.append(len(raw))
            assert sum(bytes_read) <= 9
            return raw

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Reader())
    # A stale hint models growth/truncation between fstat and read. It must not
    # determine which bytes are accepted, even if a read returns short of its request.
    monkeypatch.setattr(
        common.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG, st_size=hint)
    )
    if overflow:
        with pytest.raises(TraceError) as error:
            read_file(path, 8)
        assert error.value.code == "LIMIT_EXCEEDED"
    else:
        raw, receipt = read_file(path, 8, digest(payload))
        assert raw == payload
        assert receipt["sha256"] == digest(payload)
        assert receipt["size_bytes"] == 8


def test_growing_tail_is_included_in_hash_check(tmp_path, monkeypatch):
    path = tmp_path / "growing.bin"
    path.write_bytes(b"prefix-tail")
    monkeypatch.setattr(
        common.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG, st_size=6)
    )
    with pytest.raises(TraceError) as error:
        read_file(path, MAX_DOCUMENT_BYTES, digest(b"prefix"))
    assert error.value.code == "HASH_MISMATCH"


@pytest.mark.parametrize("overflow", [False, True])
def test_growth_across_multiple_chunks_is_bounded(tmp_path, monkeypatch, overflow):
    path = tmp_path / "large-growth.bin"
    payload = bytes(range(256)) * 1024
    path.write_bytes(payload)
    monkeypatch.setattr(
        common.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG, st_size=1)
    )
    if overflow:
        with pytest.raises(TraceError) as error:
            read_file(path, len(payload) - 1)
        assert error.value.code == "LIMIT_EXCEEDED"
    else:
        raw, receipt = read_file(path, len(payload), digest(payload))
        assert raw == payload and receipt["size_bytes"] == len(payload)


def test_small_file_allocation_tracks_input_not_document_limit(tmp_path):
    path = tmp_path / "small.bin"
    payload = b"x" * 1024
    path.write_bytes(payload)
    tracemalloc.start()
    try:
        raw, receipt = read_file(path, MAX_DOCUMENT_BYTES, digest(payload))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert raw == payload and receipt["size_bytes"] == len(payload)
    # Deliberately loose: catches a 64 MiB request, without fixing buffer sizes
    # or imposing wall-time/RSS expectations on other Python implementations.
    assert peak < 1024 * 1024
