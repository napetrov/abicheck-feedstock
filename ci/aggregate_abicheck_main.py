#!/usr/bin/env python3
"""Aggregate per-target abicheck-main evidence artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Mapping

EXPECTED = ("onedal", "onetbb", "onednn", "level-zero")


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for data in iter(lambda: fh.read(chunk), b""):
            h.update(data)
    return h.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def json_dump(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def find_summaries(root: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(root.rglob("summary.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        target = data.get("target") if isinstance(data, dict) else None
        if isinstance(target, str) and target in EXPECTED:
            found[target] = (path, data)
    return found


def render_summary(combined: Mapping[str, Any]) -> str:
    lines = [
        "# abicheck main — oneAPI full-source scan",
        "",
        f"- Overall status: **{combined.get('status')}**",
        f"- abicheck main SHA: `{combined.get('abicheck_main_sha') or 'mixed/missing'}`",
        f"- abicheck version: `{combined.get('abicheck_version') or 'mixed/missing'}`",
        "- Build integration: Clang for all targets; CMake compile databases or Bear for oneDAL.",
        "- Scan depth: `source` (L0 binary, L1 debug, L2 headers, L3 build context, L4 source replay, L5 graph).",
        "",
        "| Target | Status | Upstream ref | Compile units | Source files | Public headers | Unique DSOs | Snapshot wall s |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for target in EXPECTED:
        row = combined.get("targets", {}).get(target, {})
        scans = row.get("scans") or []
        scan_wall = sum(float(x.get("wall_seconds") or 0) for x in scans)
        lines.append(
            "| {target} | {status} | {ref} | {units} | {files} | {headers} | {dsos} | {wall:.3f} |".format(
                target=target,
                status=row.get("status", "missing"),
                ref=row.get("upstream_ref", ""),
                units=(row.get("compile_db") or {}).get("entries", 0),
                files=(row.get("source_inventory") or {}).get("files", 0),
                headers=(row.get("public_headers") or {}).get("files", 0),
                dsos=row.get("unique_library_count", 0),
                wall=scan_wall,
            )
        )
    lines += ["", "## Per-library source-depth snapshots", ""]
    lines += [
        "| Target | Library | Exit | Wall s | Snapshot | L3 units | L5 nodes |",
        "|---|---|---:|---:|---|---:|---:|",
    ]
    for target in EXPECTED:
        row = combined.get("targets", {}).get(target, {})
        for scan in row.get("scans") or []:
            snap = scan.get("snapshot") or {}
            lines.append(
                "| {target} | {library} | {rc} | {wall} | {ok} | {l3} | {l5} |".format(
                    target=target,
                    library=Path(str(scan.get("library", ""))).name.replace("|", "\\|"),
                    rc=scan.get("returncode", ""),
                    wall=scan.get("wall_seconds", ""),
                    ok="yes" if scan.get("snapshot") else "no",
                    l3=snap.get("l3_compile_units", ""),
                    l5=snap.get("l5_nodes", ""),
                )
            )
    missing = combined.get("missing_targets") or []
    if missing:
        lines += ["", "## Missing targets", "", *[f"- {target}" for target in missing]]
    lines.append("")
    return "\n".join(lines)


def checksums(root: Path) -> None:
    files = [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and p.name not in {"SHA256SUMS", "file_manifest.txt"}
    ]
    write_text(root / "file_manifest.txt", "\n".join(str(p.relative_to(root)) for p in files) + "\n")
    write_text(
        root / "SHA256SUMS",
        "\n".join(f"{sha256_file(p)}  {p.relative_to(root)}" for p in files) + "\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.input.resolve()
    output = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    found = find_summaries(source)
    targets: dict[str, dict[str, Any]] = {}
    for target, (summary_path, data) in found.items():
        targets[target] = data
        target_dest = output / "targets" / target
        shutil.copytree(summary_path.parent, target_dest, dirs_exist_ok=True)

    shas = {
        str(row.get("abicheck_main_sha"))
        for row in targets.values()
        if row.get("abicheck_main_sha")
    }
    versions = {
        str(row.get("abicheck_version"))
        for row in targets.values()
        if row.get("abicheck_version")
    }
    missing = [target for target in EXPECTED if target not in targets]
    states = [str(targets.get(target, {}).get("status", "missing")) for target in EXPECTED]
    if missing:
        status = "partial"
    elif all(state == "success" for state in states):
        status = "success"
    elif any(state == "success" for state in states):
        status = "partial"
    else:
        status = "failed"

    combined: dict[str, Any] = {
        "status": status,
        "abicheck_main_sha": next(iter(shas)) if len(shas) == 1 else None,
        "abicheck_main_shas": sorted(shas),
        "abicheck_version": next(iter(versions)) if len(versions) == 1 else None,
        "abicheck_versions": sorted(versions),
        "expected_targets": list(EXPECTED),
        "missing_targets": missing,
        "targets": targets,
    }
    json_dump(output / "summary.json", combined)
    write_text(output / "summary.md", render_summary(combined))

    timing_fields = [
        "target", "name", "returncode", "timed_out", "wall_seconds",
        "user_seconds", "system_seconds", "elapsed_seconds", "max_rss_mib",
        "started_at", "finished_at", "command",
    ]
    with (output / "timings.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=timing_fields)
        writer.writeheader()
        for target in EXPECTED:
            for row in targets.get(target, {}).get("timings") or []:
                metrics = row.get("time_metrics") or {}
                writer.writerow(
                    {
                        "target": target,
                        "name": row.get("name"),
                        "returncode": row.get("returncode"),
                        "timed_out": row.get("timed_out"),
                        "wall_seconds": row.get("wall_seconds"),
                        "user_seconds": metrics.get("user_seconds"),
                        "system_seconds": metrics.get("system_seconds"),
                        "elapsed_seconds": metrics.get("elapsed_seconds"),
                        "max_rss_mib": metrics.get("max_rss_mib"),
                        "started_at": row.get("started_at"),
                        "finished_at": row.get("finished_at"),
                        "command": " ".join(str(x) for x in row.get("command", [])),
                    }
                )
    checksums(output)
    print(json.dumps(combined, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
