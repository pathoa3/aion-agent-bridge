"""Classify transform-relevant VM handlers for Pass611 from safe artifacts."""
from __future__ import annotations

import csv
from parse_existing_vm_exports import ARTIFACTS, load_context, top_transform_handlers


def packet_relevance(row: dict[str, str]) -> str:
    va = row.get("handler_va", "")
    cls = row.get("behavior_class", "")
    inst = row.get("first_instruction", "")
    if va == "0x11B57796":
        return "high: prior matrix reports VM payload read but direct derived trial failed"
    if cls == "xor":
        return "medium: logical byte transform candidate"
    if cls in {"add_sub", "shift_rotate"}:
        return "medium: possible rolling state/key-byte mutation"
    if cls == "pointer_update":
        return "low-medium: possible VM pointer movement, no packet pointer confirmed"
    return "low: structural or constant operation without packet buffer proof"


def bounded_possible(row: dict[str, str]) -> str:
    cls = row.get("behavior_class", "")
    inst = row.get("first_instruction", "")
    if cls == "xor" and ("0x" in inst or ", DL" in inst or ", BL" in inst):
        return "partial"
    if cls in {"add_sub", "shift_rotate"}:
        return "partial"
    return "no"


def write_matrix(ctx: dict) -> list[dict[str, str]]:
    handlers = top_transform_handlers(ctx, minimum=20)
    rows = []
    for h in handlers:
        va = h["handler_va"]
        possible = bounded_possible(h)
        tested = "yes" if va in {"0x11B57796", "0x11B57437"} else "no"
        result = "failed_prior" if va == "0x11B57796" else ("failed_prior_literal_xor" if va == "0x11B57437" else "not_tested_insufficient_semantics")
        rows.append({
            "handler_va": va,
            "handler_index": h.get("handler_index", ""),
            "behavior_class": h.get("behavior_class", ""),
            "connects_to_p609012": "no",
            "packet_buffer_relevance": packet_relevance(h),
            "bounded_transform_possible": possible,
            "tested": tested,
            "result": result,
            "next_step": "provide full p-code/dataflow for handler" if tested == "no" else "do_not_repeat_prior_failed_direct_test",
        })
    out = ARTIFACTS / "pass611_codex_handler_trace_matrix.csv"
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["handler_va", "handler_index", "behavior_class", "connects_to_p609012", "packet_buffer_relevance", "bounded_transform_possible", "tested", "result", "next_step"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    write_matrix(load_context())
