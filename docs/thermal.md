# Saved thermal views

Version0.12 adds `thermal inspect/query/report` for self-contained HIL0.12
thermal bundles with recorded lab0.11 verification. This independent stdlib-only
domain never imports HIL/lab, accesses a camera, opens recorded paths, starts a
helper or recomputes temperatures or native JUnit XML.

```powershell
embedded-trace thermal inspect bundle.json --sha256 '<hash>' --json
embedded-trace thermal query bundle.json --sha256 '<hash>' --check cpu --status passed --json
embedded-trace thermal report bundle.json --sha256 '<hash>' --offset 8 --output new.md --json
```

Query/report support exact check ID (1..32 chars), status passed/failed/
invalid_evidence, offset0..8 and limit1..8. Invalid filters fail before reading.
Each view validates the entire original bundle and all embedded hashes/bindings,
source inventory, recorded metadata, comparisons/trends and global projection
before filtering or pagination. A passing-only or empty page retains the full
original verdict, JUnit failures/errors, source context and false qualifications.
Exit0/ok=true means successful viewing, not a passing measurement; read
`data.verdict.ok`. Input/output/consistency errors exit2; output must be new.

Raw Y16/warmup frames, GET payloads, CSV, native errors, incomplete cleanup,
telemetry, ROI spans, invalid-pixel budgets, FFC/effective gain/resolution and
valid-mask trend context stay in the bundle. Whole failed sources never yield a
scored partial subset. Apparent surface Celsius values are not chip junction
temperatures or calibrated absolute accuracy. Maxima may move between pixels;
max_delta_c is not physical point tracking or heating rate. Sensor uptime, host
receipt and Media Foundation timestamps are distinct, with no verified physical
clock/UTC, causality or cross-device alignment.

`native_recomputation_recorded=true` describes the saved native verification.
Current `native_recomputed_now`, `native_temperature_conversion_performed`,
`source_execution_performed`, `hil_import_checks_reperformed` and
`source_files_rechecked` are false. HIL's canonical XML validation is historical;
Trace checks its bound original bytes/recorded counts without reconstructing XML.
Camera/DUT identity, scene parameters, calibration, radiometric accuracy, junction
temperature, clock alignment and authority remain unverified. Hashes cannot
authenticate a coherent fabricated unsigned record set.

All data remains separate from the serial/RTT host-time timeline. Markdown prints
untruncated global verdict/JUnit counts and qualified context first, then inert
indented ASCII JSON previews capped at8192 characters per source/check, with an
explicit truncation notice. Full bytes stay in the bundle; Markdown <=1MiB.

Bundle <=32MiB/depth32; ordered explicit source inventory <=16MiB/101 files
including capture, each artifact<=1MiB. Primary report/XML<=1MiB, spec<=64KiB,
native stdout<=128KiB, manifest<=256KiB. One whole-bundle read and all embedded
verification occur for every page. Base64/JSON/canonical copies add allocations;
limits are not RSS or latency guarantees. Acceptance records whole-view costs
and warm/cold conditions; this viewer is not a cache or service.

The11 zipped repository fixtures were produced by native lab0.11 on synthetic
frames; tests and installed smoke use bounded temporary copies. No real camera,
vendor ABI or physical temperature reference was qualified. Existing digital,
waveform and load formats retain historical producer/verifier compatibility and
also accept the new native0.11 matrices, without relabeling their original bytes.
