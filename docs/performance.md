# Bounded file reads

Version 0.13.1 uses the opened regular file's size as an allocation hint. The
previous reader requested the full byte limit plus one, temporarily allocating
about 64 MiB even for a tiny timeline. Input/output schemas and CLI syntax are
unchanged. Every query still reads, hashes and validates its complete timeline
before filtering; an empty page retains the complete source and verdict context.

The size hint is not an integrity check or a promise that a file is immutable.
The reader probes beyond the hinted size, handles short reads, and consumes any
additional bytes up to the existing limit plus one. Growth beyond that limit is
rejected. Accepted bytes, including a growing tail, all participate in SHA-256.
Path/link and regular-file checks are unchanged.

For stable files, temporary byte storage scales with the actual file size.
Growth or short reads use bounded 64 KiB chunks and a final join, which can
temporarily retain roughly twice the accepted byte count plus chunk overhead.
The reader never accepts a prefix merely because the earlier size hint was
smaller. It retains the existing one-extra-byte overflow check.

## Local measurements

Measured on Windows, CPython 3.13, 2026-10-29: one warmup, seven timed in-process
calls and a separate tracemalloc call per operation. Before is source 0.13.0;
after uses this reader. The same saved normal, frozen and host-timeout sensor
evidence was reused without rerunning a simulator or native capture.

| Operation | Median before / after | Python peak before / after |
| --- | --- | --- |
| 1 KiB input, 64 MiB limit | 8.09 / 0.19 ms | 67,118,235 / 11,095 B |
| 8 MiB input, 64 MiB limit | 14.27 / 7.80 ms | 67,118,241 / 8,398,685 B |
| Two-source sensor import | 25.73 / 7.31 ms | 8,720,696 / 380,764 B |
| Saved normal timeline inspect | 12.12 / 3.83 ms | 67,118,275 / 287,730 B |
| Frozen evidence, empty page | 11.53 / 2.10 ms | 67,118,265 / 147,711 B |
| Timeout evidence, empty page | 9.25 / 0.55 ms | 67,118,301 / 42,863 B |

Both CPython 3.11 and 3.13 produced identical before/after result hashes for all
16 operations, including failed/empty views. Audit hooks rejected process and
network starts, writes, and attempts by a saved view to reopen original sources.
These are warm host observations, not RSS, cold IO, process startup costs or an
SLA. Full parsing/validation still scales with document size; this change does
not make evidence queries streaming or constant-memory operations.

Tests cover empty/exact-limit/overflow inputs, stale smaller and larger size
hints, short reads, multi-chunk growth, tail hash mismatch and small-file peak
allocation. Existing path, special-file, malformed-evidence and full-query
validation tests continue to apply.
