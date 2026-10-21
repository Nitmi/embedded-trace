# Offline simulation evidence

Version 0.3.0 accepts `sim-runner-report` in the existing trace input v1 format.
It reads a selected SHA-256-bound sim-runner 0.1/0.2 Renode report or 0.2 QEMU
report and the declared adjacent files. It never launches sim-runner/QEMU,
imports their code, connects to a device or follows instructions from logs.

```json
{
  "schema_version": "embedded-trace.input.v1",
  "sources": [{
    "id": "c3-a",
    "format": "sim-runner-report",
    "path": "runs/c3-a/report.json",
    "sha256": "<native-report-sha256>",
    "clock_domain": "sim-c3-a"
  }]
}
```

Use the existing `correlate`, `inspect`, `query` and `report` commands. The optional
HIL Runner 0.3.0 simulation suite emits this input automatically, including valid
failed native reports. No Toolkit/station update or component execution occurs.

Only fixed `nrf52840-uart-v1` and `esp32c3-ram-uart-v1` reports are supported.
Only the declared fixed basenames next to the report are opened; recorded absolute
paths are untrusted metadata. Hashes, sizes, plan/lock/firmware/model bindings,
simulation flags and declared successful process cleanup are checked. Missing,
changed, traversing or linked evidence fails before timeline output is created.
Source limits include all adjacent evidence bytes: at most 8 MiB per source and
16 MiB across sources, 128 KiB per native report, 20,000 records/events. These are
Trace limits and can be smaller than a simulator's maximum capture size.

Trace does not rerun native readiness assertions, emulate the CPU or establish
the authenticity of a report. `native_summary_verified=false` and
`native_assertions_reexecuted=false` remain explicit. A native failed verdict
stays `capture_outcome=failed`, with `correlated_with_warnings`, even if the UART
contains READY and plausible heartbeats. Import/report exit zero means a valid
offline view, not a successful simulation. Gate CI on the native/HIL result.

UART is stored as `simulation.uart`, never `serial.rx` or `rtt.up`. There are no
per-byte timestamps. Each line carries the whole recorded host run window, not
invented generation/arrival times or measured virtual time. Native virtual-time
metadata is retained as reported. `saved_records` explicitly describes the
selected report and synthetic 64 KiB UART file containers; byte spans refer to
those containers, not fictitious native recorder events. Partial/binary lines
retain raw bytes and warnings. The complete UART can be reconstructed and hashed.

Simulation and device captures must use different clock-domain IDs. IDs remain
user declarations, not verified synchronization. Sorting these sources does not
establish causality, shared clocks, firmware identity or physical acceptance.
Source metadata and Markdown previews visibly retain simulation kind, profile,
recorded status, host window and false physical verification. Rendering escapes
log text as data and keeps bounded previews separate from full timeline bytes.

The timeline can be moved and inspected/reported without the original native
directory. Native files are checked on import, not silently reopened during
query/report. Saved timeline inspection verifies its bound bytes and layout,
including UART reconstruction, and is not a signature or proof of real hardware.
