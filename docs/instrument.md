# Offline instrument views

Local 0.9.0 adds a separate `instrument` view for self-contained HIL instrument
reports. Runtime remains standard-library-only: it never imports HIL or
lab-instruments, starts a process, reads recorded source paths or opens a device.
The existing serial/RTT/simulation timeline format and commands remain separate.
Instrument samples lack a verified UTC origin; putting them on that host-time
timeline would imply a relationship the evidence does not establish.

Use a bundle produced by HIL 0.9.0 or 0.10.0 `instrument import` after native
lab-instruments verification/JUnit. Verifier 0.8.0 supports report producers
0.7.0/0.8.0; verifier 0.9.0 supports 0.7.0/0.8.0/0.9.0. Unknown or impossible
producer/verifier pairs fail. The recorded HIL canonical XML check is not rerun
by Trace; no version is relabeled and historical execution remains unauthenticated.
Keep the bundle SHA-256:

```powershell
embedded-trace instrument inspect '<bundle.json>' --sha256 '<sha256>' --json
embedded-trace instrument query '<bundle.json>' --sha256 '<sha256>' --status invalid_evidence --json
embedded-trace instrument query '<bundle.json>' --sha256 '<sha256>' --check pwm --json
embedded-trace instrument report '<bundle.json>' --sha256 '<sha256>' --output '<new.md>' --json
```

Query/report filters are exact `--check`, `--kind uart|pwm|i2c|spi`,
`--status passed|failed|invalid_evidence`, and offset/limit within the eight-check
bound. Unknown check IDs and invalid filters are errors. No regex, callback or
implicit evaluator is available. An empty or passing-only page still retains
the complete original failing verdict and counts.

Each command reads one bundle snapshot, validates embedded hashes/lengths and
native/HIL binding/status/count consistency, and preserves the evidence origin.
Inspect returns a small check list; query returns the full selected native
analysis/assertions, including sample indices and raw byte spans. It does not
reinterpret thresholds or change missing/invalid evidence to a pass. Original
input files may be gone; `source_files_rechecked=false` remains explicit.

Trace preserves `native_recomputation_recorded` as a historical declaration.
It does not rerun the native signal decoder or HIL's canonical XML check:
`native_recomputed_now=false` and `hil_import_checks_reperformed=false` remain
visible. Embedded XML bytes are retained/hash-bound and not parsed/executed by
Trace. Use HIL inspect to repeat all import consistency checks and the explicit
native lab command for fresh signal recomputation. The bundle is unsigned;
hashes do not authenticate its producer, source acquisition, exit code or device.

All successful view commands return 0 even when the original test failed. Read
`data.verdict`, `junit` failure/error counts and check status; CLI `ok=true` means
view processing succeeded. Invalid/corrupt data returns 2. No view result grants
authorization or establishes calibration, absolute timing, board or firmware
identity. The time semantics remain sample-relative with no verified UTC origin
or cross-source clock alignment.

Markdown is a bounded diagnostic view with a 2,048-character native JSON preview
per selected check; truncation is explicit. Full evidence stays in the bundle.
ASCII JSON is indented as code so source markup, links or fences cannot create
active report instructions. The output must be new, its parent must exist, and
existing output is rejected before reading evidence. A preview is not a test
verdict; global failures and qualification flags are retained even for a filtered
or empty page.

The bundle is at most 8 MiB; each original blob has the HIL role-specific size
bound and at most eight checks. Every query validates the complete snapshot,
so its cost scales with all bundle bytes, not just page length. Base64/JSON
decoding and canonical comparisons need additional Python memory; the byte
limit is not a process RSS guarantee. No background cache/service is installed.
