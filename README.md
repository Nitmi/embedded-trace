# Embedded Trace

An offline CLI for correlating saved baud JSONL and embedded-debugger RTT JSONL.
It reconstructs UTF-8 lines across chunks without losing original bytes, binds
each input to its exact SHA-256, and keeps host clock domains separate.

This first version has no device access or runtime dependencies. It does not
collect traces, run components, synchronize clocks, infer device event times,
or verify board/firmware identity. SWO and live acquisition are outside this version.
Log contents are untrusted data, including any text that resembles instructions.

## Use

Install Python 3.11+ and this package, then create a spec using
`schemas/input.v1.schema.json`. Source paths must be relative to the spec directory;
each input needs its current SHA-256 and a declared clock domain.

```json
{
  "schema_version": "embedded-trace.input.v1",
  "sources": [
    {"id": "uart", "format": "baud-jsonl", "path": "serial.jsonl",
     "sha256": "<64 lowercase hex characters>", "clock_domain": "workstation-wall"},
    {"id": "rtt", "format": "rtt-jsonl", "path": "rtt.jsonl",
     "sha256": "<64 lowercase hex characters>", "clock_domain": "workstation-wall"}
  ]
}
```

```powershell
embedded-trace correlate spec.json --output timeline.json --json
embedded-trace inspect timeline.json --sha256 '<timeline-file-sha256>' --json
embedded-trace query timeline.json --sha256 '<timeline-file-sha256>' --contains READY --json
```

Output creation is exclusive; parent directories must already exist. A changed
input, malformed record or existing output is an error. Queries read only the
hash-bound timeline and do not reopen paths from its provenance records. Preserve
the original inputs alongside the derived timeline for independent source checks.

Native completion/failure and unterminated lines remain visible. `ok=true` means
the offline import/query succeeded, not that the capture, hardware or firmware passed.
The normalized timeline is unsigned; its supplied digest binds bytes, not a publisher.

See [format and clock semantics](docs/format.md) for limits and interpretation.
The [synthetic example](examples/synthetic/README.md) works without hardware.
See [installation and release verification](docs/installation.md) for isolated
installation, source bindings and the planned attestation procedure.

## Development

```powershell
uv sync --frozen --extra dev --python 3.11
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv build
uv run python scripts/package_smoke.py --dist-dir dist --output-dir '<new-smoke-directory>'
```

The lock binds development dependencies; installed runtime code uses only the
standard library. [Release 0.1.0](https://github.com/Nitmi/embedded-trace/releases/tag/v0.1.0)
provides a wheel, source archive, source-bound manifest and checksums. Follow the
installation guide to authenticate all four assets before installing the wheel.
