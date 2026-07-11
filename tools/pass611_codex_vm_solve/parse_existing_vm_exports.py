"""Parse existing safe VM export artifacts for Pass611.

This module intentionally reads only text/CSV/JSON artifacts. It does not execute
or load target binaries and does not emit packet payload bytes or private hashes.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

REPO = Path(r"C:\AionTools\aion-agent-bridge")
ARTIFACTS = REPO / "artifacts"
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
LOCAL_OUT = PRIVATE / "outbox" / "pass611_codex_vm_solve_local"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(read_text(path))


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def normalize_va(value: str) -> str:
    v = (value or "").strip().strip("`")
    if not v:
        return ""
    if v.lower().startswith("0x"):
        try:
            return f"0x{int(v, 16):08X}"
        except ValueError:
            return v
    try:
        return f"0x{int(v, 16):08X}"
    except ValueError:
        return v


def load_context() -> dict[str, Any]:
    return {
        "pass609_decision": read_json(ARTIFACTS / "pass609_codex_source_hunt_decision.json"),
        "pass609_summary": read_text(ARTIFACTS / "pass609_codex_source_hunt_summary.md"),
        "pass609_candidates": read_csv(ARTIFACTS / "pass609_codex_source_hunt_candidates.csv"),
        "pass610_codex_decision": read_json(ARTIFACTS / "pass610_codex_vm_decision.json"),
        "pass610_antigravity_decision": read_json(ARTIFACTS / "pass610_antigravity_vm_cleartext_decision.json"),
        "pass610_antigravity_summary": read_text(ARTIFACTS / "pass610_antigravity_vm_cleartext_summary.md"),
        "pass610_execution_model": read_text(ARTIFACTS / "pass610_antigravity_vm_execution_model.md"),
        "pass610_handler_classification": read_csv(ARTIFACTS / "pass610_antigravity_vm_handler_classification.csv"),
        "pass610_transform_candidates": read_csv(ARTIFACTS / "pass610_antigravity_vm_transform_candidates.csv"),
        "pass610_trace_matrix_text": read_text(ARTIFACTS / "pass610_antigravity_handler_trace_matrix.csv"),
        "pass610_p609_edge_text": read_text(ARTIFACTS / "pass610_antigravity_p609012_edge_trace.md"),
        "pass610_p609_dataflow": read_csv(ARTIFACTS / "pass610_antigravity_p609012_dataflow.csv"),
    }


def top_transform_handlers(ctx: dict[str, Any], minimum: int = 20) -> list[dict[str, str]]:
    classifications = {normalize_va(r.get("handler_va", "")): r for r in ctx["pass610_handler_classification"]}
    rows: list[dict[str, str]] = []
    for cand in ctx["pass610_transform_candidates"]:
        va = normalize_va(cand.get("handler_va", ""))
        cls = classifications.get(va, {})
        rows.append({
            "handler_va": va,
            "handler_index": cand.get("handler_index", ""),
            "behavior_class": cand.get("behavior_class", cls.get("classification", "unknown")),
            "first_instruction": cls.get("first_instruction", ""),
            "occurrence_count": cls.get("occurrence_count", ""),
            "why_relevant": cand.get("why_relevant", cls.get("notes", "")),
            "confidence": cand.get("confidence", "medium"),
        })
    if len(rows) < minimum:
        priority = {"xor", "add_sub", "shift_rotate", "pointer_update", "constant_load", "branch_dispatch"}
        existing = {r["handler_va"] for r in rows}
        for cls in ctx["pass610_handler_classification"]:
            va = normalize_va(cls.get("handler_va", ""))
            if va in existing or cls.get("classification", "") not in priority:
                continue
            rows.append({
                "handler_va": va,
                "handler_index": str(len(rows) + 1),
                "behavior_class": cls.get("classification", "unknown"),
                "first_instruction": cls.get("first_instruction", ""),
                "occurrence_count": cls.get("occurrence_count", ""),
                "why_relevant": cls.get("notes", ""),
                "confidence": "low",
            })
            if len(rows) >= minimum:
                break
    return rows
