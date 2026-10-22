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

Each query validates all bundle bytes (up to 8 MiB), regardless of page length.
Base64/JSON parsing and comparison allocate extra memory. Include measured wall
time and Python allocation peaks in acceptance, separate from process RSS and
interpreter startup. No background cache/service is introduced by this view.
