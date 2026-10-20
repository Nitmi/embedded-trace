# Format, clocks and limits

`correlate` consumes only the files explicitly listed in a spec. Each path is
portable and relative to that spec's directory; absolute paths, traversal, Windows
reserved names/streams, links and reparse points are rejected. File bytes are
read into a bounded snapshot and checked against the supplied lowercase SHA-256.
This is byte identity relative to the supplied spec, not publisher authentication.
Filesystem checks are not protection against a hostile concurrent filesystem owner.

## Supported saved formats

- `baud-jsonl`: the Recorder's UTF-8 JSONL with `ts`, `type`, and for `recv`/`send`,
  exact `raw_base64`, `bytes`, `step`. The source's already-decoded `text` is not
  used as raw evidence. Native non-payload events remain present as metadata.
- `rtt-jsonl`: `embedded-debugger.rtt-evidence.v1`, starting with
  `capture.started`, followed by the channel and sequential hex payload chunks.
  Channel selection, capture ID, monotonic elapsed counters, sequence, byte
  cursors/lengths and successful final payload hash/counts/cleanup are checked.
  Failed or interrupted captures retain visible payload and an explicit
  failed/partial outcome. This reader does not verify the full native plan's
  authorization policy, probe identity, summary binding or target cleanup.

JSONL must end with a complete record newline. A missing successful capture finish
can be represented as partial, but malformed/truncated JSON is rejected. Duplicate
fields, invalid UTF-8/Unicode escapes, nonfinite numbers and unsupported record
types are errors. Baud logs without a terminal record are partial, including
excerpts; concatenating separate runs is rejected when their lifecycle is present.

RX, TX and RTT are independent byte streams. Complete LF/CRLF lines can span
chunks and UTF-8 character boundaries. A baud RX step change closes any pending
fragment, and a TX record boundary closes a command fragment. No partial line is
silently joined across those boundaries. Unterminated tails remain explicit;
binary data retains base64 and SHA-256 with `text=null`, without replacement
characters. Every line includes byte-span references to its original JSONL records.

## Clock semantics

Each source must declare a clock domain; different domains remain grouped apart.
Sharing a name is a user assertion that host observations can be compared, not a
verification that hosts are synchronized. There are no automatic offsets, shared
zero, drift estimation, target-time extraction or causal conclusions.

Baud timestamps are Recorder event creation times, sometimes at the end of an
entire read window. RTT timestamps are host chunk record creation times. They do
not establish device event generation or individual byte arrival. A line spanning
chunks carries first/last observed timestamps and the minimum/maximum over all
participating records. This is an envelope of host recording observations, not
a confidence interval for when the firmware emitted the line.

Timestamps require timezone-qualified RFC3339, explicit `T`, at most 9 fractional
digits and the supported UTC epoch range 1970–9999. Unknown `-00:00` offsets,
leap seconds, floating-point epochs and missing zones are rejected. Unix
nanoseconds are computed with integer arithmetic and emitted as decimal strings
so JSON consumers do not lose precision.

The output sorts by clock domain, minimum host record time, source index, then
source ordinal. Equal times are stable tie-breaks, not simultaneity or causality.
Wall-clock regressions create source warnings. Original record indices and source
ordinals remain available even if wall-time sorting changes their displayed order.
A source ordinal orders normalized events by their completing native record;
the line's first/last record indices separately preserve a multi-record span.
RTT elapsed time must remain nondecreasing; it stays local to that capture and is
not used to manufacture a wall-time alignment.

## Query and verification

`inspect` and `query` require the exact timeline file SHA-256 and validate its
layout, IDs, ordering, line bytes/hashes/views and spans. They do not reopen source
paths; `source_files_rechecked=false` states this explicitly. Keep native inputs
with the timeline to re-run correlation after checking their hashes independently.
The normalized timeline is unsigned and does not authenticate its producer.

`query --contains` is case-sensitive UTF-8 substring matching over reconstructed
lines, including lines split across source chunks. It does not search metadata
or binary lines, run regular expressions, or interpret log text as commands.
`--since`/`--until` select inclusive overlap with the host-recorded envelopes.
Source/domain filters can be combined. Pagination is by filtered event index;
the same bound timeline yields stable pages. The JSON envelope always keeps
hardware, authorization, clock-alignment and runtime-identity claims false.

## Bounds and writes

At most 8 sources; 8 MiB per source, 16 MiB total source bytes, 20,000 total native
records and normalized events, 128 KiB per JSONL record, 64 KiB per reconstructed
line, JSON depth 32, and 64 MiB per normalized output/input timeline. RTT additionally
keeps its native 4,096 chunks, 4 KiB per chunk and 1 MiB payload maximum.
Queries return at most 100 events per page with a 512-character text filter.

Only `correlate --output` writes a derived file, with exclusive creation after
input checks finish. Parent directories must already exist; existing outputs are
never overwritten. An I/O failure can retain a partial new output for diagnosis.
Exit 0 means successful offline processing, 2 means invalid inputs or a refused
output, and 4 means host I/O failure. A successful import of a failed capture is
still `ok=true` with `correlated_with_warnings` and its failed source outcome.
