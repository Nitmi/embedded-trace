# Embedded Trace handoff

Read this file and AGENTS.md before a new task. The active workspace HANDOFF.md
and desktop development plan track cross-repository progress.

Release CI found that tests/test_load.py imported scripts as a package, relying
on `python -m pytest` putting the checkout on sys.path. The CI `pytest` launcher
does not guarantee this. Reuse test_release's explicit file-loaded release
module instead of changing sys.path, the runtime or the CI entry point. Exercise
both invocation forms in release acceptance. This changes tests/handoff only;
the accepted 0.11 wheel must remain byte-identical. No tag existed at the fix.

Current local work is 0.11.0 on feat/offline-load-evidence; 0.10.0 was already
published, so older unpublished notes below are historical. See docs/load.md.
The load protocol kernel is vendored byte-identically with HIL, but both runtimes
remain independent stdlib-only packages. It checks original bindings and record
consistency, not native SCPI replay or HIL's canonical XML reconstruction.

Keep raw-query cache keys command-specific and verify transaction indices against
transcript command starts. Reject huge integers by bounds before float conversion.
Whole-bundle validation precedes all filters, with global verdict/JUnit outside
any truncated Markdown source preview. Unknown cleanup and failed-source partial
measurements never become a passing selected page. Installed inventory is now
21 package files (15 modules, six schemas); cold smoke must use only Trace's
wheel. Joint lab0.10/HIL0.11/Trace0.11 acceptance also covers actual digital and
waveform outputs, including unchanged older producers reverified by lab0.10.

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
- Preserve hash-bound waveform fixture bytes via `-text`; Git normalization may
  otherwise change source archive payloads despite clean status and passing tests.
  Keep one named bundle per scenario; generator reruns must not add duplicate
  `*-bundle.json` copies beside the canonical fixture names.

## Release-preparation digital compatibility correction

Current lab0.9 generates digital reports as well as waveform reports. Keep the
digital path usable with the jointly selected new component versions: verifier
0.8 supports producers0.7/0.8, verifier0.9 supports producers0.7/0.8/0.9. Reject
unknown or impossible version pairs, retain original hashes/verdicts/flags, and
keep `hil_import_checks_reperformed=false`; Trace still does not rebuild XML or
decode signals. Actual lab0.9/HIL fixtures are in examples/instrument-09, including
a genuine native0.9 recheck of a saved producer0.8 report. Installed smoke covers
these five cases in addition to historical digital/waveform views. This fixes a
cross-component release-preflight gap, not a change in decoding semantics.
The initial 140b8eca candidate remains frozen; release preparation must select
the newly validated candidate source and hashes before requesting publication.
