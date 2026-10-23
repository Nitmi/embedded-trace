# Saved analog waveform views

Local 0.10.0 reads `embedded-hil-runner.waveform-report.v1` artifacts produced by
HIL Runner 0.10.0 from lab-instruments 0.9.0 AD3/SDS804X waveform verification.
No lab/HIL package is required at runtime. It opens only the explicitly supplied
bundle, never recorded source paths, executables, SDKs or network endpoints.

```powershell
python -I -B -m embedded_trace waveform inspect bundle.json --sha256 <hash> --json
python -I -B -m embedded_trace waveform query bundle.json --sha256 <hash> --channel 1 --status failed --json
python -I -B -m embedded_trace waveform report bundle.json --sha256 <hash> --check supply --output new.md --json
```

Query/report accept exact check ID, channel 1..4, status
`passed|failed|invalid_evidence`, offset 0..8 and limit 1..8. Filters combine.
An empty or passing-only page retains the entire original verdict and JUnit
failure/error counts. CLI exit 0 means successful processing, not a passing test.
Exit 2 means invalid input/binding/format/output. Existing outputs are rejected.

All embedded bytes, explicit source inventory, hashes, report/verification
bindings, summaries and recorded metric comparisons are checked before filtering.
Source qualification, cleanup/freshness, raw spans, voltage conversion metadata,
all six metrics and original assertions survive in selected checks. Native voltage
recomputation and HIL canonical JUnit validation are recorded, not performed now:
`native_recomputed_now=false`, `hil_import_checks_reperformed=false`. This is not
an independent decoder or proof of authenticated historical execution. The XML
is hash-bound but not reparsed/reconstructed by Trace.

Markdown contains bounded, inert indented ASCII JSON, with at most 8,192 preview
characters per selected check and a 1 MiB output cap. Full evidence remains in
the bundle; a truncated preview never replaces it. A view preserves test-double
origin and false calibration, bandwidth, clipping absence, physical timing,
DUT identity, UTC sample origin and cross-channel alignment claims.
RMS includes DC; AC RMS only removes the mean. No clock synchronization or
causality follows from descriptor-relative sample times. Waveforms use their own
view, separate from serial/RTT host-clock timelines.

Every query reads and validates the complete bundle, up to 20 MiB, regardless of
pagination. Embedded native sources total at most 8 MiB/1,615 files, plus bounded
report/spec/response/XML and manifest data. Each source file is at most 1 MiB;
native zero-byte wire responses are retained. JSON depth is limited to 32.
Hashing, base64 and parsed copies add CPU/memory, so limits are not RSS guarantees.
Measure full-bundle costs separately from interpreter startup; there is no
background service or cache. Included examples use synthetic captures only.
