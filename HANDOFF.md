# Embedded Trace handoff

Read this file and AGENTS.md before a new task. The active workspace HANDOFF.md
and desktop development plan track cross-repository progress.

Local 0.9.0 instrument inspect/query/report consumes HIL 0.9.0 self-contained
saved evidence. Keep runtime standard-library-only and file-only. Do not import
HIL/lab packages or launch their executables. See docs/instrument.md.

Pitfalls and boundaries:

- A filtered or empty page must retain the complete original failing verdict,
  JUnit failure/error counts and qualification flags. View processing success
  does not mean a test passed. Invalid evidence never becomes skipped.
- Preserve sample indices/raw byte spans. No verified UTC sample origin exists,
  so instrument evidence uses its own view instead of the host-time timeline.
- Validate embedded bytes and bindings before viewing. Native recomputation and
  HIL's canonical XML check are recorded, not rerun; keep their false current
  verification flags explicit. A signed/authenticated source is not established.
- Use canonical JSON when comparing evidence so bool/int/float differences are
  not lost. Hashing a rewritten bundle does not make inconsistent native/HIL
  status or source bindings valid.
- Markdown excerpts are inert indented ASCII JSON with explicit preview limits.
  Full native evidence stays in the bundle. Do not render untrusted log markup.
- Changes to installed modules/schemas must update the exact package smoke file
  inventory. New schema/fixture files must be staged before sdist construction.
- The release verifier has a separate version-aware exact wheel inventory.
  Instrument 0.9.0 requires both instrument.py and its report schema there too;
  runtime/package-smoke success alone does not qualify a release build.

Each query validates all bundle bytes (up to 8 MiB), regardless of page length.
Base64/JSON parsing and comparison allocate extra memory. Include measured wall
time and Python allocation peaks in acceptance, separate from process RSS and
interpreter startup. No background cache/service is introduced by this view.

## Local 0.10.0 saved waveform views

The separate `waveform inspect/query/report` domain reads self-contained HIL
0.10.0 waveform bundles with recorded lab 0.9.0 verification. There is no lab/HIL
runtime dependency, native voltage conversion, SCPI replay or device execution.
Native recomputation and HIL canonical XML validation remain historical records;
`native_recomputed_now` and `hil_import_checks_reperformed` are false.

- Preserve the whole original failed verdict/JUnit errors under check/channel/
  status filtering, pagination and empty pages. Keep native metrics/raw spans,
  source cleanup/freshness, descriptor context and all false measurement claims.
  Sample times stay outside the host-clock timeline; a hash authenticates no
  execution, physical instrument, DUT, calibration, clipping or bandwidth.
- Read the selected bundle once, at most 20 MiB; validate all embedded bytes,
  ordered explicit source inventory (8 MiB/1,615 native files), hashes and
  verification/summary/metric bindings before filtering. Never open path labels.
  SDS empty RX snapshots are valid; absent files are not. JSON canonical key
  sorting does not define native source inventory order.
- Markdown uses inert indented ASCII JSON with a bounded 8,192-character check
  preview and 1 MiB output cap; retain full evidence in the original artifact.
- New waveform.py and schema must be in both installed smoke's 18-file inventory
  and release verifier's >=0.10 exact inventory. Earlier 0.9 releases retain
  their old inventory and digital artifact compatibility. Use 99.0.0 for an
  unknown-producer negative fixture now that HIL 0.10 is supported.
- Shared test environments may contain old ordinary wheels: explicitly select
  process-only src for source tests, and use fresh wheels/isolated imports for
  installed smoke. Keep Py3.11/3.13 full and changed-path regressions separate
  from the native Replay qualification, which is HIL's responsibility.
- Measure whole-bundle validation even for a passing-only or empty query.
  Base64, JSON and canonical comparisons allocate copies, beyond file limits;
  Python allocation peaks do not establish process RSS or worst-case latency.
