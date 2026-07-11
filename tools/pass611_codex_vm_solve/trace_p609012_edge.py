"""Trace the P609-012 candidate edge from existing static text artifacts."""
from __future__ import annotations

import csv
from pathlib import Path
from parse_existing_vm_exports import ARTIFACTS, load_context

EDGE = "0x114731E0..0x114731F5"


def build_rows(ctx: dict) -> list[dict[str, str]]:
    existing = ctx.get("pass610_p609_dataflow") or []
    if existing:
        rows = []
        for row in existing:
            rows.append({
                "edge_va": row.get("edge_va", ""),
                "source_register": row.get("source_register", ""),
                "target_register": row.get("target_register", ""),
                "memory_ref": row.get("memory_ref", ""),
                "operation": row.get("operation", ""),
                "possible_meaning": row.get("possible_meaning", ""),
                "confidence": row.get("confidence", ""),
                "next_step": row.get("next_step", ""),
            })
        rows.append({
            "edge_va": EDGE,
            "source_register": "RSI/RBX",
            "target_register": "packet buffer/length",
            "memory_ref": "none confirmed",
            "operation": "dataflow check",
            "possible_meaning": "No programmatic RSI/RBX-to-packet-buffer bridge is present in available static exports; prior bytes parse as obfuscation/noise or unaligned code.",
            "confidence": "medium",
            "next_step": "do_not_use_edge_as_transform_source",
        })
        return rows
    return [{
        "edge_va": EDGE,
        "source_register": "unknown",
        "target_register": "unknown",
        "memory_ref": "missing p-code/disassembly",
        "operation": "blocked",
        "possible_meaning": "Cannot prove packet buffer bridge without generated disassembly/p-code covering the edge.",
        "confidence": "low",
        "next_step": "provide pass8b_target_pcode/disassembly for edge",
    }]


def write_outputs(ctx: dict) -> list[dict[str, str]]:
    rows = build_rows(ctx)
    csv_path = ARTIFACTS / "pass611_codex_p609012_dataflow.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["edge_va", "source_register", "target_register", "memory_ref", "operation", "possible_meaning", "confidence", "next_step"])
        writer.writeheader()
        writer.writerows(rows)
    verdict = "rejected" if any(r["next_step"] == "do_not_use_edge_as_transform_source" for r in rows) else "unresolved"
    md = f"""# Pass611 Codex P609-012 Edge Trace\n\nEdge: `{EDGE}`\n\nCodex re-read the available Pass609/Pass610 text and CSV artifacts and searched the static export helper references. No target binary was executed.\n\n## Result\n\n- Packet-buffer bridge status: **{verdict}**.\n- RSI/RBX mapping to packet payload writes: **not confirmed**.\n- Connection to handler `0x11B57796`, `0x11B5932F`, or dispatch table `0x11B54E6F`: **not proven by this edge**.\n- Available evidence says the bytes at the edge decode as unaligned/obfuscation-noise style instructions rather than a VM context bridge.\n\n## Consequence\n\nThis edge should not be used to derive a decoder transform. The useful VM work moves to handler semantics, but the available artifacts expose mostly first-instruction classifications rather than complete p-code/dataflow for each handler.\n"""
    (ARTIFACTS / "pass611_codex_p609012_edge_trace.md").write_text(md, encoding="utf-8")
    return rows


if __name__ == "__main__":
    write_outputs(load_context())
