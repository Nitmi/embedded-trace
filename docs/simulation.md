# Offline simulation evidence

## Experimental ESP-EMU WASM in 0.8.0

Embedded Trace 0.8.0 accepts `embedded-sim-runner.esp-wasm-report.v1`
for `esp32c3-wasm-flash-v1`. Only the fixed adjacent artifacts and four fixed
`component/` files are read. Source evidence stays bounded to 12 MiB (96 MiB
for a simulation selection); recorded absolute paths are never followed.

`uart.bin` spans refer to UTF-8 encoded ASCII strings returned by WASM, not
verified original UART bytes. `raw_uart_bytes_verified=false`, `model_limits`,
opaque ROM/eFuse `initial_state`, unmeasured `virtual_time`, native assertions,
native errors and runtime observations stay in inspect/query/Markdown summaries
even when filters exclude metadata. Budget exhaustion remains failed; timeout
observations/assertions remain null. Requested instruction upper bounds and
model cycle counters or cycles-per-us claims are not measured physical timing.
A guest restart request is a stop reason; `restart_performed=false` is retained.

Successful imports never promote `passed_with_model_limits` or failed captures.
Trace validates saved layout, hashes and declarations without loading simulator
code, launching Node, accessing live paths or rerunning firmware assertion policy.

## Fault reports in 0.7.0

The `nrf52840-gpio-timer-fault-v1` adapter preserves `fault_scenario`,
`fault_scope`, the plan-bound `fault_request`, full native `fault_evidence` and
`native_errors`, as well as the native nominal verdict and virtual-time declaration.
Null assertions after a timeout remain null; no effect or regression verdict is
invented. The four effect selections and explicit `none` control are fixed model
inputs, not evidence of a physical fault or root cause.

GPIO input/output, TIMER0 counter and IRQ-enable values bind to complete
`SIM_FAULT_OBS_n` records in raw stdout. Each span includes its original bytes,
offsets and SHA-256, including the final newline. A truncated final record cannot
be treated as a complete observation. Inspect/query/Markdown validate saved span
layout without reopening sources and retain fault context even for UART-only
filters. Native policy is not rerun; successful import/inspection never converts
a failed regression or unknown effect into a pass.

Version 0.7.0 accepts `sim-runner-report` in the existing trace input v1 format.
It reads a selected SHA-256-bound sim-runner 0.1/0.2/0.3 Renode report, QEMU RAM
report, 0.3/0.4/0.5 C3 ESP-IDF Flash report, 0.4/0.5 Renode GPIO/TIMER0 report,
or 0.5/0.6 Xtensa S3 ESP-IDF Flash report, 0.6 GPIO/TIMER0 fault report and declared
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
HIL Runner 0.3/0.4/0.5/0.6 simulation suite emits this input automatically, including valid
failed native reports. No Toolkit/station update or component execution occurs.

Only fixed `nrf52840-uart-v1`, `esp32c3-ram-uart-v1` and
`esp32c3-idf-flash-v1`, `nrf52840-gpio-timer-v1`, `nrf52840-gpio-timer-fault-v1`
and `esp32s3-idf-flash-v1` reports are supported.
Only the declared fixed basenames (and four fixed WASM `component/` files) next to the report are opened; recorded absolute
paths are untrusted metadata. Hashes, sizes, plan/lock/firmware/model bindings,
simulation flags and declared successful process cleanup are checked. Missing,
changed, traversing or linked evidence fails before timeline output is created.
Source limits include all adjacent evidence bytes: 8 MiB for old profiles/device
captures; 12 MiB for Flash/WASM (including staged model inputs and runtime files).
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

## ESP32-S3 identity and clock

S3's native `qemu-s3-flash-report.v1` has a distinct plan schema, backend
`espressif-qemu-xtensa` and staged `esp32s3_rev0_rom.bin`. It uses the same 12 MiB
Flash source budget. Import binds the recorded runtime backend/version/archive,
Xtensa executable declaration, ROM hash and model identity to the native plan
and report. Original executable/lock absolute paths are never opened. These
checks preserve saved consistency; they do not authenticate the runtime or
rerun native S3 readiness/diagnostic policy.

`backend`, `backend_version`, `runtime_archive_sha256`, `virtual_time` and
`app_core_markers` survive inspect/query/Markdown, including filtered UART views.
Core markers are bounded native declarations; unevaluated assertions remain
null. Host UART windows and `qemu_device_clock_unmeasured` are separate:
`elapsed_ns=null`, `budget_enforced=false`, no borrowed C3 icount interpretation
or invented timing measurement. Summary relabelling is rejected against the
native metadata saved inside the timeline. Query/report still work after the
source directory is removed. Flash diagnostics, qualified/failed outcomes and
false coverage/security claims remain unchanged; complete SMP, debug attachment,
Flash commands or physical behavior cannot be inferred from this view.

## Sensor evidence

Trace 0.13 accepts native `embedded-sim-runner.sensor-report.v1` for the fixed
0.8.0 `nrf52840-i2c-sensor-v1` profile. It binds the saved plan, script, clock,
fault request and nine-file Renode artifact layout before constructing a view.
The 8 MiB source budget is unchanged. It never opens the original runtime paths.

`sensor_evidence` preserves all native assertions, up to 16 guest samples and
four paused TMP103/TWI0/TIMER0 observations. Signed negative temperature bytes
remain distinct from unsigned register values. Fault effects, nominal failures,
native errors and unevaluated null assertions are retained without rerunning
firmware or sensor acceptance policy. A successful import is no simulation pass.

Each observation uses the native stdout offset/length/hash to save exact raw
`sensor_observation_spans`. Import checks those bytes and the recorded values;
later views validate the embedded spans and metadata without reopening sources.
Saved consistency is neither authenticity nor independent model execution.
All sensor fields, spans and failed/unknown outcomes survive UART filters and
empty pages. Markdown keeps source context outside truncated event previews.

The coverage, physical timing, sensor accuracy and I2C electrical verification
flags stay false. Observation times are requested paused RunFor boundaries;
sample ticks are guest 250 kHz TIMER0 IRQ captures. UART events still use the
entire recorded host run window. No calibrated/electrical/physical measurement,
clock synchronization or real board acceptance follows from these declarations.
Whole timeline validation precedes filters; an empty page has the same input
verification cost. Sixteen samples/four spans bound the added projection cost.
