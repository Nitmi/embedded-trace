"""Independent views of self-contained saved load evidence; no native/XML replay."""

from __future__ import annotations

import json

from . import __version__
from . import load_protocol as protocol
from .common import checked_path, digest, integer, read_file, require, write_new_bytes

FLAGS = protocol.FLAGS
canonical = protocol.canonical


def load(path, sha):
    raw, ref = read_file(path, protocol.MAX_BUNDLE, sha)
    bundle = protocol.decode(raw)
    expected = protocol.project(bundle["import_spec"], bundle["inputs"], bundle["producer_version"])
    protocol.same(bundle, expected, "HIL load projection differs from embedded evidence")
    return bundle, ref


def view(path, sha, *, check=None, phase=None, status=None, offset=0, limit=8):
    integer(offset, "offset", 0, 8)
    integer(limit, "limit", 1, 8)
    require(phase in (None, "before_load", "loaded", "observe"), "invalid phase filter")
    require(status in (None, "passed", "failed", "invalid_evidence"), "invalid status filter")
    require(check is None or type(check) is str and 0 < len(check) <= 64, "invalid check filter")
    bundle, ref = load(path, sha)
    checks = [
        c
        for c in bundle["checks"]
        if (check is None or c["id"] == check)
        and (phase is None or c["phase"] == phase)
        and (status is None or c["status"] == status)
    ]
    return dict(
        input=ref,
        viewer_version=__version__,
        source=bundle["source"],
        verdict={k: bundle[k] for k in ("ok", "status", "summary")},
        junit=bundle["junit"],
        native_exit_code=bundle["native_exit_code"],
        native_recomputation_recorded=True,
        hil_import_checks_reperformed=False,
        source_files_rechecked=False,
        clock_alignment_verified=False,
        time_semantics=protocol.TIME,
        matched_checks=len(checks),
        selected_checks=len(checks[offset : offset + limit]),
        checks=checks[offset : offset + limit],
        **FLAGS,
    )


def markdown(path, sha, output, **filters):
    checked_path(output.parent)
    require(not output.exists() and not output.is_symlink(), "output already exists")
    value = view(path, sha, **filters)
    text = (
        "# Saved load checks\n\nGlobal verdict: "
        + value["verdict"]["status"]
        + "\n\nNative SCPI replay and JUnit validation are recorded, not repeated here. "
        "V/I/P are sequential queries; current instrument state, DUT, calibration and "
        "physical timing remain unverified. Full raw evidence remains in the bundle.\n\n"
    )
    # Partial source measurements can be large: summaries and check previews share
    # the same bounded inert formatting. The full view JSON retains every field.
    global_details = {**{k: value[k] for k in ("verdict", "junit", "time_semantics")}, **FLAGS}
    text += (
        "\n".join(
            "    " + line
            for line in json.dumps(global_details, ensure_ascii=True, indent=2).splitlines()
        )
        + "\n"
    )
    for item in (value["source"], *value["checks"]):
        preview = json.dumps(item, ensure_ascii=True, sort_keys=True, indent=2)
        if len(preview) > 8192:
            preview = preview[:8192] + "\n[preview truncated; consult full bundle/JSON]"
        text += "\n" + "\n".join("    " + line for line in preview.splitlines()) + "\n"
    encoded = text.encode("ascii")
    require(len(encoded) <= 1048576, "load Markdown exceeds 1 MiB", "LIMIT_EXCEEDED")
    write_new_bytes(output, encoded)
    return {
        **value,
        "output": dict(path=str(output), sha256=digest(encoded), size_bytes=len(encoded)),
    }
