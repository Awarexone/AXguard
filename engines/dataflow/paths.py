"""Build source→sink taint paths with steps, confidence, and evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.app_model.discover import read_text, rel_path
from engines.dataflow.controls import classify_taint_state, find_controls_in_region
from engines.dataflow.propagate import propagate_file, sink_uses_taint
from engines.dataflow.schema import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_UNKNOWN,
    TAINTED,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    evidence,
)


def build_taint_paths(
    root: Path,
    files: list[Path],
    sources: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Construct intraprocedural taint paths.

    Returns (taint_paths, flows, controls_seen_all).
    """
    sources_by_file: dict[str, list[dict[str, Any]]] = {}
    for s in sources:
        sources_by_file.setdefault(str(s.get("file") or ""), []).append(s)

    sinks_by_file: dict[str, list[dict[str, Any]]] = {}
    for s in sinks:
        sinks_by_file.setdefault(str(s.get("file") or ""), []).append(s)

    paths: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    all_controls: list[dict[str, Any]] = []
    ctrl_ids: set[str] = set()

    for fpath in files:
        rel = rel_path(fpath, root)
        file_sources = sources_by_file.get(rel, [])
        file_sinks = sinks_by_file.get(rel, [])
        if not file_sources or not file_sinks:
            continue

        content = read_text(fpath)
        if not content:
            continue
        lines = content.splitlines()

        # Seed named sources (prefer assignment-bound names)
        seeds: dict[str, dict[str, Any]] = {}
        for src in file_sources:
            name = str(src.get("name") or "")
            if name and name not in {
                "request_args",
                "request_param",
                "request_headers",
                "request_cookies",
                "webhook",
                "env",
                "ai_output",
            }:
                seeds[name] = {
                    "source_id": src["id"],
                    "source": src,
                    "file": rel,
                    "line": src.get("line"),
                }
            # Also seed generic request carrier when kind is request_*
            kind = str(src.get("kind") or "")
            if kind.startswith("request") or kind == "webhook":
                seeds.setdefault(
                    "request",
                    {
                        "source_id": src["id"],
                        "source": src,
                        "file": rel,
                        "line": src.get("line"),
                    },
                )

        if not seeds:
            continue

        tainted = propagate_file(content, seeds)

        for sink in file_sinks:
            sink_line_no = int(sink.get("line") or 0)
            if sink_line_no < 1 or sink_line_no > len(lines):
                continue
            sink_line = lines[sink_line_no - 1]
            # Skip comment-only (already filtered in sinks, belt-and-suspenders)
            if sink_line.lstrip().startswith("#") or sink_line.lstrip().startswith("//"):
                continue

            hits = sink_uses_taint(sink_line, tainted)
            if not hits:
                # Same-function heuristic: source above sink in file + sink uses
                # request.* directly already covered; also f-string SQL with request
                if not _nearby_source_reaches(file_sources, sink, sink_line):
                    continue
                hits = ["request"]

            # Pick primary source: earliest named hit's donor, else nearest above sink
            donor_meta = None
            for h in hits:
                if h in tainted:
                    donor_meta = tainted[h]
                    break
            primary_src = (donor_meta or {}).get("source")
            if primary_src is None:
                primary_src = _nearest_source_above(file_sources, sink_line_no)
            if primary_src is None:
                continue

            src_line = int(primary_src.get("line") or 0)
            # Require source at or above sink for intra-procedural confidence
            if src_line > sink_line_no + 2:
                # Allow small reorder; otherwise skip (prefer unknown over inventing)
                continue

            region_controls = find_controls_in_region(
                content,
                file=rel,
                start_line=src_line or 1,
                end_line=sink_line_no,
                sink_type=str(sink.get("type") or ""),
            )
            for c in region_controls:
                if c["id"] not in ctrl_ids:
                    ctrl_ids.add(c["id"])
                    all_controls.append(c)

            taint_state = classify_taint_state(
                region_controls,
                sink_type=str(sink.get("type") or ""),
                trust_level=str(primary_src.get("trust_level") or TRUST_UNTRUSTED),
            )

            # Never claim SANITIZED without parameterization/allowlist confirmed
            conf = _path_confidence(
                primary_src, sink, hits, taint_state, region_controls
            )

            steps = _build_steps(primary_src, tainted, hits, sink, lines)
            path = {
                "id": f"path.{primary_src.get('id')}->{sink.get('id')}",
                "source": {
                    "id": primary_src.get("id"),
                    "kind": primary_src.get("kind"),
                    "name": primary_src.get("name"),
                    "trust_level": primary_src.get("trust_level"),
                    "file": primary_src.get("file"),
                    "line": primary_src.get("line"),
                    "endpoint": primary_src.get("endpoint"),
                },
                "sink": {
                    "id": sink.get("id"),
                    "type": sink.get("type"),
                    "symbol": sink.get("symbol"),
                    "file": sink.get("file"),
                    "line": sink.get("line"),
                },
                "steps": steps,
                "taint_state": taint_state,
                "controls_seen": [c["id"] for c in region_controls],
                "confidence": conf,
                "evidence": [
                    evidence(
                        rel,
                        src_line,
                        symbol=str(primary_src.get("name")),
                        reason="Taint source",
                        snippet=lines[src_line - 1] if 0 < src_line <= len(lines) else None,
                    ),
                    evidence(
                        rel,
                        sink_line_no,
                        symbol=str(sink.get("symbol")),
                        reason=f"Sink type={sink.get('type')} uses tainted names={hits}",
                        snippet=sink_line,
                    ),
                ],
            }
            paths.append(path)

            flows.append(
                {
                    "source_id": primary_src.get("id"),
                    "sink_id": sink.get("id"),
                    "path_id": path["id"],
                    "taint_state": taint_state,
                    "confidence": conf,
                    "file": rel,
                }
            )

    paths.sort(
        key=lambda p: (
            (p.get("source") or {}).get("file") or "",
            (p.get("source") or {}).get("line") or 0,
            (p.get("sink") or {}).get("line") or 0,
        )
    )
    return paths, flows, all_controls


def _nearby_source_reaches(
    sources: list[dict[str, Any]], sink: dict[str, Any], sink_line: str
) -> bool:
    """True when a request-like source is above the sink and sink line looks dynamic."""
    sink_ln = int(sink.get("line") or 0)
    has_src = any(
        int(s.get("line") or 0) <= sink_ln
        and str(s.get("trust_level")) != TRUST_TRUSTED
        for s in sources
    )
    if not has_src:
        return False
    # Dynamic arg: variable identifier inside call, or f-string / concat
    if re_search_dynamic(sink_line):
        return True
    return False


def re_search_dynamic(line: str) -> bool:
    import re

    if re.search(r"\bf['\"]", line):
        return True
    if re.search(r"request\.(args|form|values|json)", line):
        return True
    if re.search(r"req\.(query|params|body)", line):
        return True
    # requests.get(url) style — identifier arg not a string literal
    if re.search(
        r"(?:requests|httpx|fetch|axios)\.[\w]+\(\s*[A-Za-z_][\w\.]*\s*[,)]",
        line,
    ):
        return True
    if re.search(r"\.(?:execute|executemany)\(\s*[A-Za-z_][\w\.]*\s*[,)]", line):
        return True
    return False


def _nearest_source_above(
    sources: list[dict[str, Any]], sink_line: int
) -> dict[str, Any] | None:
    candidates = [s for s in sources if int(s.get("line") or 0) <= sink_line]
    if not candidates:
        return None
    # Prefer named assignment sources
    named = [
        s
        for s in candidates
        if s.get("name")
        and str(s.get("name"))
        not in {
            "request_args",
            "request_param",
            "request_headers",
            "request_cookies",
            "webhook",
            "env",
            "ai_output",
        }
    ]
    pool = named or candidates
    return max(pool, key=lambda s: int(s.get("line") or 0))


def _build_steps(
    source: dict[str, Any],
    tainted: dict[str, dict[str, Any]],
    hits: list[str],
    sink: dict[str, Any],
    lines: list[str],
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = [
        {
            "kind": "source",
            "name": source.get("name"),
            "file": source.get("file"),
            "line": source.get("line"),
            "detail": f"kind={source.get('kind')}",
        }
    ]
    # Intermediate assignments for hit names
    for h in hits:
        meta = tainted.get(h)
        if not meta:
            continue
        via = meta.get("via")
        if via and via != "source":
            ln = int(meta.get("line") or 0)
            steps.append(
                {
                    "kind": "propagate",
                    "name": h,
                    "file": source.get("file"),
                    "line": ln,
                    "detail": f"via={via}",
                }
            )
    steps.append(
        {
            "kind": "sink",
            "name": sink.get("symbol"),
            "file": sink.get("file"),
            "line": sink.get("line"),
            "detail": f"type={sink.get('type')}",
        }
    )
    return steps


def _path_confidence(
    source: dict[str, Any],
    sink: dict[str, Any],
    hits: list[str],
    taint_state: str,
    controls: list[dict[str, Any]],
) -> str:
    src_conf = source.get("confidence", CONFIDENCE_UNKNOWN)
    sink_conf = sink.get("confidence", CONFIDENCE_UNKNOWN)

    # Direct named var at sink + confirmed source → confirmed (if still TAINTED)
    named_hit = any(h not in {"request", "req"} for h in hits)
    if (
        named_hit
        and src_conf == CONFIDENCE_CONFIRMED
        and sink_conf == CONFIDENCE_CONFIRMED
        and taint_state == TAINTED
    ):
        return CONFIDENCE_CONFIRMED

    if named_hit and taint_state == TAINTED:
        return CONFIDENCE_LIKELY

    if taint_state in {"SANITIZED", "VALIDATED", "PARTIALLY_SANITIZED"}:
        return CONFIDENCE_LIKELY if controls else CONFIDENCE_UNKNOWN

    return CONFIDENCE_UNKNOWN
