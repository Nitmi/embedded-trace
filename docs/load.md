# Saved load views

These file-only, standard-library commands consume HIL 0.11.0
`embedded-hil-runner.load-report.v1`. They open no device or process and need no
HIL or lab installation. Use a separate load view because query windows do not
provide verified simultaneous instrument samples or a UTC sample timeline.

```powershell
embedded-trace load inspect bundle.json --sha256 <bundle-sha256> --json
embedded-trace load query bundle.json --sha256 <bundle-sha256> --phase loaded --status passed --offset 0 --limit 8 --json
embedded-trace load report bundle.json --sha256 <bundle-sha256> --check rail_5v --output report.md --json
```

Filters select exact check ID, phase (`before_load`, `loaded`, `observe`) and
status (`passed`, `failed`, `invalid_evidence`). Offset is 0..8, limit 1..8.
Every view validates the entire bundle before applying filters. Empty and
passing-only pages retain the complete original verdict, JUnit failures/errors,
source errors, identity, recorded effects and cleanup. Source partial readings
from a failed acquisition remain unscored. `ok=true` and exit 0 mean view
processing succeeded; use `data.verdict.ok` to determine test success.

The viewer checks embedded original bytes/hashes/sizes, explicit manifest roles,
native verification bindings and the recorded verdict, metrics, comparisons,
raw query byte spans/transactions and source projection. It does not follow any
recorded source path, reopen original files, launch lab, repeat native SCPI replay
or reconstruct native XML. HIL's complete XML check is recorded, not repeated:
`hil_import_checks_reperformed=false`, `source_files_rechecked=false`,
`native_recomputed_now=false`, `native_scpi_replay_performed=false`,
`source_execution_performed=false`. `native_recomputation_recorded=true` is
historical evidence, not a new native run. SHA-256 is binding, not authenticity;
`report_authenticated=false` remains explicit.

V/I/P are sequential queries. Power is the returned instrument value; means
are arithmetic, not time-weighted; there is no energy integration. Host query
windows do not establish physical timing or simultaneous samples. Recorded OFF
and cleanup do not establish current instrument state. Physical device/DUT
identity, calibration, timing, simultaneous measurement and clock alignment
remain unverified; no new output command, executable or hardware access occurs.

Raw Base64 RX/TX references and JSONL byte spans remain exact inside the bundle.
Native producer/verifier must be lab 0.10.0; HIL producer must be 0.11.0. The
six example bundles are generated from actual lab output using localhost
protocol doubles and do not qualify physical devices. Existing digital and
waveform schemas remain separate; their explicit lab 0.10 compatibility fixtures
also include an unchanged digital 0.8 report reverified by 0.10.

Bundle limit: 16 MiB, JSON depth 32; seven source limits are report/capture/XML/
transcript 1 MiB each, spec 64 KiB, native stdout 128 KiB, plan 32 KiB, manifest
16 KiB. Only a failed-source transcript can be empty. A view reads one whole
bundle and processes all embedded evidence regardless of page length. JSON and
base64/canonical copies add allocation cost; limits are not RSS guarantees.

Markdown always includes untruncated global verdict and JUnit counts. Source
context and each selected check are inert indented ASCII JSON previews capped
at 8192 characters with explicit truncation; complete bytes remain in the
bundle/JSON view. Output is exclusive and capped at 1 MiB. Invalid filters and
existing output are rejected before reading the bundle. Acceptance measures
whole-bundle views, not just selected rows.
