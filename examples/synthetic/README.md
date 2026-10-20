# Synthetic fixture

These hand-written records are test data, not a hardware capture or an authorized
native plan. Their payloads are `READY\n` split across two serial records and
`RTT\n` in one RTT record. Both declare the same synthetic host clock solely for
demonstrating time-window overlap and stable tie-breaks.

From the repository, after installation:

```powershell
embedded-trace correlate examples/synthetic/input.json --output demo-timeline.json --json
```

Use the returned `output.sha256` for `inspect` or `query --contains READY`.
The reconstructed serial line spans host record times 1–3 ms; the RTT line is
recorded at 2 ms. This overlap provides no target event order or causal claim.
Use a new output filename for each invocation; existing outputs are refused.
