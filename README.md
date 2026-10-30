# Embedded Trace

Local **0.14.0** adds [SPI/LM74 saved evidence](docs/simulation.md#spi-evidence-in-local-0140):
signed fractional values, model snapshots and a separate byte-frame-slip span,
with failures and unknown effects retained in full, filtered and empty views.
The runtime remains offline and standard-library-only.

Local **0.13.1** reduces temporary allocations for small evidence files while
retaining complete size and SHA-256 checks. See [performance notes](docs/performance.md)
for the measured costs, bounds and file-growth behavior.

Local **0.13.0** adds [sensor evidence views](docs/simulation.md#sensor-evidence)
for fixed sim-runner 0.8.0 nRF52840 TWI0/TMP103 reports. Filtered and empty pages
retain native signed samples, fault outcomes, raw model observation spans and
unverified accuracy/electrical/timing claims.

Local **0.12.0** adds [saved thermal views](docs/thermal.md): inspect, filter and
report ROI checks while retaining all original bytes, global failed verdicts,
invalid evidence and unverified temperature/identity/clock claims.

Version **0.11.0** adds [saved load evidence views](docs/load.md): inspect,
filter and report SDL1020X-E assertions with original V/I/P query bytes,
complete verdicts and failed/unknown cleanup. Actual lab 0.10 digital/waveform
reports are also accepted without changing their evidence formats.

The **0.10.0** release adds [saved analog waveform views](docs/waveform.md):
filter AD3/SDS804X checks by ID, channel or status while retaining the full
verdict, voltage metrics, raw byte spans and unverified measurement claims.

The **0.9.0** release adds [instrument evidence views](docs/instrument.md): inspect,
filter and report saved HIL instrument checks with original raw sample references,
global failures and source qualification, separate from timestamped timelines.

The published [0.8.0 release](https://github.com/Nitmi/embedded-trace/releases/tag/v0.8.0) adds offline ESP-EMU WASM reports from sim-runner 0.7.0.
String UART provenance, model limitations, restart requests, budget failures and
unknown observations stay visible in filtered views;
see [simulation evidence](docs/simulation.md).

The [0.7.0 release](https://github.com/Nitmi/embedded-trace/releases/tag/v0.7.0)
adds sim-runner 0.6.0 GPIO/TIMER0 fault reports.
Native fault analysis, failures and unknown effects stay visible in filtered
queries and Markdown, with raw counter/IRQ snapshot spans. Successful import
never changes the native verdict.

It also preserves Xtensa ESP32-S3 Flash identity, unmeasured clock and
core declarations alongside Renode GPIO/TIMER0 reports with separate guest samples,
paused model observations and raw stdout spans. It retains ESP-IDF Flash reports and explicit
`succeeded_with_model_limits` outcomes to offline `sim-runner-report` input alongside saved
baud/RTT logs. [Simulation evidence](docs/simulation.md) retains the recorded
native verdict, exact artifact bindings and UART file spans. Simulation and
device captures use separate clock domains; report/query success never promotes
a failed simulation to acceptance. Existing serial/RTT formats remain supported.

An offline CLI for correlating saved baud JSONL and embedded-debugger RTT JSONL.
It reconstructs UTF-8 lines across chunks without losing original bytes, binds
each input to its exact SHA-256, and keeps host clock domains separate.

The CLI has no device access or runtime dependencies. It does not
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
embedded-trace report timeline.json --sha256 '<timeline-file-sha256>' --contains READY --output ready.md --json
```

Output creation is exclusive; parent directories must already exist. A changed
input, malformed record or existing output is an error. Queries and reports read only the
hash-bound timeline and do not reopen paths from its provenance records. Preserve
the original inputs alongside the derived timeline for independent source checks.

Native completion/failure and unterminated lines remain visible. `ok=true` means
the offline import/query succeeded, not that the capture, hardware or firmware passed.
The normalized timeline is unsigned; its supplied digest binds bytes, not a publisher.

The optional Markdown report records the timeline digest, capture outcomes,
clock domains and a bounded page of event previews. It accepts the same filters
as `query`. Every line preview cites its event ID, original record indices,
payload digest and byte spans; truncation is explicit. Native records and binary
lines remain distinguishable. Log text is rendered as inert JSON code, never as
Markdown instructions, links or HTML. Keep the complete timeline and native logs
for full evidence; the report is a readable view, not a hardware verdict.

The report command, introduced in 0.2.0, can also read existing
0.1.0 timelines; the published 0.1.0 release does not include the report command.

See [format and clock semantics](docs/format.md) for limits and interpretation.
The [synthetic example](examples/synthetic/README.md) works without hardware.
See [installation and release verification](docs/installation.md) for isolated
installation, source bindings and the attestation procedure.

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
standard library. [Release 0.7.0](https://github.com/Nitmi/embedded-trace/releases/tag/v0.7.0)
provides a wheel, source archive, source-bound manifest and checksums. Follow the
installation guide to authenticate all four assets before installing the wheel.
