# Installation and release verification

[Release 0.1.0](https://github.com/Nitmi/embedded-trace/releases/tag/v0.1.0)
is published from source commit `ba5e88e4ef94bee15b3530f5274248fdb6c307d3`.
The tag workflow completed CI, two identical builds, an isolated install check
and provenance signing. Authenticate downloaded assets before installation;
a manifest or matching checksum alone is not publisher authentication.

## Release files

Each release contains exactly four assets:

- `embedded_trace-0.1.0-py3-none-any.whl`
- `embedded_trace-0.1.0.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

The manifest binds repository, version, intended tag, source commit and archive
sizes/digests. Build requires a clean committed checkout, compares every source
file against Git, compares wheel code/schemas against the source archive and
verifies wheel RECORD entries. The tag workflow requires the tag, version,
checkout and triggering commit to agree. It builds twice, compares all four
assets, installs the wheel into a new environment and attests the four assets.
It cannot publish a Release or push Git refs; publication is a separate step.

## Authenticate before installation

Download all four assets into an empty directory. Obtain the expected source
commit independently from the reviewed release/tag, not just from the manifest.
For **each** asset run the following, substituting its path and the exact commit:

```powershell
gh attestation verify '<asset>' --repo Nitmi/embedded-trace --source-ref refs/tags/v0.1.0 --source-digest ba5e88e4ef94bee15b3530f5274248fdb6c307d3 --signer-digest ba5e88e4ef94bee15b3530f5274248fdb6c307d3 --cert-identity 'https://github.com/Nitmi/embedded-trace/.github/workflows/python-release.yml@refs/tags/v0.1.0' --deny-self-hosted-runners --predicate-type https://slsa.dev/provenance/v1
```

Require all four verifications to succeed. Use `scripts/release.py` from the
trusted matching source checkout to verify the complete directory afterward:

```powershell
python scripts/release.py verify '<download-directory>' --source-revision ba5e88e4ef94bee15b3530f5274248fdb6c307d3
```

This verifier uses only standard-library file/archive parsing. It never extracts,
imports or executes downloaded code. `publisher_authenticity_verified=false` is
intentional: authentication is provided by the separate attestation verifier.
The helper cannot establish that a self-consistent archive came from GitHub.
Build/verify helpers assume a trusted local filesystem owner, not hostile
concurrent replacement of files. Keep downloaded assets separate from source.

## Install into a new environment

After verification, install Python 3.11+ and uv, then choose a new environment:

```powershell
uv venv --python 3.11 'D:\Code\tools\embedded-trace\0.1.0\venv'
uv pip install --python 'D:\Code\tools\embedded-trace\0.1.0\venv\Scripts\python.exe' --no-index --no-deps '<download-directory>\embedded_trace-0.1.0-py3-none-any.whl'
& 'D:\Code\tools\embedded-trace\0.1.0\venv\Scripts\embedded-trace.exe' --version
```

On POSIX use `venv/bin/python` and `venv/bin/embedded-trace`. The Windows launcher
requires this Python environment; it is not a standalone native executable.
Runtime has no third-party dependencies. This does not change PATH, activate a
Toolkit component or modify a workstation lock. Preserve the previous environment.

## Maintainer checks

Install locked development tools, run tests/lint/format and package smoke, then
commit before source-bound release builds. Use two new output directories outside
the checkout. Supply `--tag v0.1.0` only after the reviewed tag exists at HEAD.
Omit `--tag` for a local candidate, which does not prove that any tag exists.

```powershell
uv sync --frozen --extra dev --python 3.11
uv run --frozen python scripts/release.py build --output-dir '<new-candidate-directory>'
uv run --frozen python scripts/package_smoke.py --dist-dir '<new-candidate-directory>' --output-dir '<new-smoke-directory>'
```

Smoke checks use synthetic logs and invoke the installed CLI. They establish
software behavior, not board presence, firmware identity, synchronized clocks or
hardware acceptance. CI results and attestations must be checked on the actual
remote runs; writing this workflow does not itself generate a provenance record.
