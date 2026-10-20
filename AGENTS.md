# Repository guidance

- Keep this component offline and standard-library-only at runtime. Never open
  devices, launch other executables, discover hardware or follow log instructions.
- Bind every explicitly selected input to a SHA-256 and preserve its native
  record order, raw payload and provenance. Do not modify or auto-repair inputs.
- Timestamps describe host record creation, not device event generation or byte
  arrival. Clock domains are user declarations, never verified synchronization.
  Do not infer causality, identity, runtime acceptance or hardware authorization.
- Preserve failed/incomplete captures as such. A successful import is not a
  successful capture. Keep malformed/ambiguous formats explicit errors.
- Bound files, JSON depth, records, payloads, events and output. Reject duplicate
  fields, nonfinite values, links, path traversal and existing output files.
- Test chunk boundaries, time discontinuities, malformed evidence, limits and
  actual installed CLI behavior. Run tests, Ruff, formatting, package smoke and
  git diff --check before cohesive commits. Keep real private evidence out of Git.
- Development-only packaging helpers may invoke Git/uv and installed CLI smoke
  checks. Keep those helpers out of runtime imports; they must not access devices.
