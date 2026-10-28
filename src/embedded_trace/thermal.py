"""Independent views of saved radiometric evidence, no native/XML replay."""

from __future__ import annotations

import json

from . import __version__
from . import thermal_protocol as protocol
from .common import checked_path, digest, integer, read_file, require, write_new_bytes

FLAGS = protocol.FLAGS
canonical = protocol.canonical


def load(path, sha):
    raw, ref = read_file(path, protocol.MAX_BUNDLE, sha)
    bundle = protocol.decode(raw)
    expected = protocol.project(
        bundle["import_spec"], bundle["inputs"], bundle["source_files"], bundle["producer_version"]
    )
    protocol.same(bundle, expected, "HIL thermal projection differs from embedded evidence")
    return bundle, ref


def view(path, sha, *, check=None, status=None, offset=0, limit=8):
    integer(offset, "offset", 0, 8)
    integer(limit, "limit", 1, 8)
    require(status in (None, "passed", "failed", "invalid_evidence"), "invalid status filter")
    require(check is None or type(check) is str and 0 < len(check) <= 32, "invalid check filter")
    bundle, ref = load(path, sha)
    checks = [
        c
        for c in bundle["checks"]
        if (check is None or c["id"] == check) and (status is None or c["status"] == status)
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
        "# Saved thermal checks\n\nGlobal verdict: "
        + value["verdict"]["status"]
        + "\n\nNative temperature conversion and JUnit verification are recorded, not repeated. "
        "Apparent surface temperatures do not establish junction temperature, calibrated accuracy, "
        "scene parameters, DUT identity or a verified physical clock. "
        "Full original bytes remain in the bundle.\n\n"
    )
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
    require(len(encoded) <= 1048576, "thermal Markdown exceeds 1 MiB", "LIMIT_EXCEEDED")
    write_new_bytes(output, encoded)
    return {
        **value,
        "output": dict(path=str(output), sha256=digest(encoded), size_bytes=len(encoded)),
    }
