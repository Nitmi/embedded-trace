# Offline simulation evidence

Version 0.5.0 accepts `sim-runner-report` in the existing trace input v1 format.
It reads a selected SHA-256-bound sim-runner 0.1/0.2/0.3 Renode report, QEMU RAM
report, 0.3/0.4 ESP-IDF Flash report or 0.4 Renode GPIO/TIMER0 report and declared
adjacent files. It never launches sim-runner/QEMU,
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
HIL Runner 0.3/0.4/0.5 simulation suite emits this input automatically, including valid
failed native reports. No Toolkit/station update or component execution occurs.

Only fixed `nrf52840-uart-v1`, `esp32c3-ram-uart-v1` and
`esp32c3-idf-flash-v1` and `nrf52840-gpio-timer-v1` reports are supported.
Only the declared fixed basenames next to the report are opened; recorded absolute
paths are untrusted metadata. Hashes, sizes, plan/lock/firmware/model bindings,
simulation flags and declared successful process cleanup are checked. Missing,
changed, traversing or linked evidence fails before timeline output is created.
Source limits include all adjacent evidence bytes: 8 MiB for old profiles/device
captures; 12 MiB for Flash (including two 4 MiB images, ROM and eFuse copies).
Physical captures still total at most 16 MiB, including in mixed inputs. Inputs
with explicitly selected simulation reports have a 96 MiB total budget for up
to eight sources. Native reports remain bounded to 128 KiB, timeline JSON to
64 MiB and records/events to 20,000. These are
Trace limits and can be smaller than a simulator's maximum capture size.

Trace does not rerun native readiness assertions, emulate the CPU or establish
the authenticity of a report. `native_summary_verified=false` and
`native_assertions_reexecuted=false` remain explicit. A native failed verdict
stays `capture_outcome=failed`, with `correlated_with_warnings`, even if the UART
contains READY and plausible heartbeats. Import/report exit zero means a valid
offline view, not a successful simulation. Gate CI on the native/HIL result.

Native `passed_with_model_limits` becomes
`capture_outcome=succeeded_with_model_limits`, retains `recorded_status`, all
native `model_diagnostics` counts/meanings and both false coverage/security
claims, and makes the timeline `correlated_with_warnings`. Query, inspect and
Markdown retain that outcome. During import diagnostic counts must match the
bound raw stderr. This is saved-evidence consistency, not a rerun of native
readiness/diagnostic policy. Query/report validate summaries against the native
metadata already in the timeline; they reject removed limitations/warnings or
flattened verdicts and do not reopen source files.

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

## GPIO / TIMER0 evidence

The new native `gpio-timer-report.v1` uses the Renode artifact layout and 8 MiB
source limit. Import checks the saved plan/script binding and native coverage
and observation labels. `gpio_evidence` retains the native `samples` and
`model_observations` arrays, including null when assertions were not evaluated.
Their shape and sizes are bounded; Trace does not rerun the fixed pin schedule,
period/IRQ assertions or firmware readiness policy.

For each recorded model observation, import finds the exact ASCII stdout record,
checks its OUT/IN integers and saves `gpio_observation_spans` with byte offsets,
raw base64 and SHA-256. Surrounding Windows locale-encoded paths/logs are never
decoded or rewritten. The referenced artifact remains `backend.stdout.bin`.
Guest samples remain declarations from native assertions and raw UART evidence;
the timeline does not claim independent verification of guest code semantics.

`requested_virtual_ms` is the requested paused RunFor boundary, not a measured
UART event time. `timer_ticks` is a guest-reported 250 kHz capture in TIMER0 IRQ,
not host time. UART line events still carry the complete host run window.
Inspect/query/Markdown retain all three meanings, native status, both false
`model_coverage_complete` / `physical_timing_verified` fields, the samples and
raw observation spans even if a query selects only one UART line.

A native GPIO `passed` stays `capture_outcome=succeeded`; it is not converted to
the Flash profile's qualified-success enum. The source also carries
`model_coverage_incomplete=1` warning, making the timeline
`correlated_with_warnings`. A derived view cannot delete that warning, promote
coverage, alter summary/clock labels or change observation bytes/layout while
remaining internally valid. Query/report validate the saved timeline without
reopening sources. Span checks are saved layout/integrity checks, not signatures,
revalidation of original byte offsets or independent model execution.
