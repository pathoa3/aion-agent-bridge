#!/usr/bin/env python3
"""Git-safe Path B caller/xref inspector for Pass631."""

import argparse
import csv
import json
from pathlib import Path

PATH_B_TERMS = [
    "11B45846", "11B52CE5", "1195D94A", "11B566DD", "11B566B4",
    "11B56999", "11B56075", "11B59337", "11B59832", "11B59838", "11B5625B",
]
PATH_B_NAMES = {
    "0x1195D94A": "entry/thunk to FUN_11b45846",
    "0x11B52CE5": "thunk_FUN_11b45846",
    "0x11B45846": "FUN_11b45846",
    "0x11B566DD": "FUN_11b566dd thunk to 0x11B566B4",
    "0x11B566B4": "embedded prologue before FUN_11b56999",
    "0x11B56999": "FUN_11b56999",
    "0x11B56075": "thunk_FUN_11b59337",
    "0x11B59337": "FUN_11b59337",
    "0x11B59832": "missing FUN_11b59832 export",
    "0x11B59838": "FUN_11b59838 dispatcher setup",
    "0x11B5625B": "dispatcher FUN_11b5625b",
}


def read_csv(path):
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def text(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def find_file(export_dir, token, suffix):
    matches = list(export_dir.glob("*%s*%s" % (token.upper(), suffix))) + list(export_dir.glob("*%s*%s" % (token.lower(), suffix)))
    return matches[0] if matches else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default=r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
    ap.add_argument("--repo-root", default=r"C:\AionTools\aion-agent-bridge")
    ns = ap.parse_args()
    export_dir = Path(ns.export_dir)
    repo = Path(ns.repo_root)
    art = repo / "artifacts"

    call_edges = read_csv(export_dir / "path_b_call_edges.csv") or read_csv(export_dir / "call_edges.csv")
    funcs = read_csv(export_dir / "path_b_functions.csv") or read_csv(export_dir / "candidate_functions.csv")
    imports = read_csv(export_dir / "path_b_import_refs.csv") or read_csv(export_dir / "import_refs.csv")
    xrefs = read_csv(export_dir / "path_b_xrefs.csv")

    path_b_edges = []
    for row in call_edges:
        joined = " ".join(row.values()).upper()
        if any(t in joined for t in PATH_B_TERMS):
            path_b_edges.append(row)

    caller_rows = []
    seen = set()
    for row in funcs:
        joined = " ".join(row.values()).upper()
        if not any(t in joined for t in PATH_B_TERMS):
            continue
        entry = row.get("entry") or row.get("function_entry") or row.get("address_requested") or ""
        name = row.get("name") or row.get("function") or ""
        key = (entry, name)
        if key in seen:
            continue
        seen.add(key)
        outgoing = [e for e in path_b_edges if e.get("from_entry") == entry]
        incoming = [e for e in path_b_edges if e.get("to_entry") == entry]
        is_entry = entry.upper() == "0X1195D94A" or name.lower() == "entry"
        recv_related = any((imp.get("caller_entry") == entry or imp.get("caller_name") == name) for imp in imports)
        caller_rows.append({
            "caller_id": "P631-CALL-%03d" % (len(caller_rows) + 1),
            "function_or_address": (entry + " " + name).strip(),
            "role": PATH_B_NAMES.get(entry.upper().replace("0X", "0x"), "Path B graph function"),
            "incoming_path_b_edges": len(incoming),
            "outgoing_path_b_edges": len(outgoing),
            "entry_or_thunk_only": str(is_entry or "thunk" in name.lower()).lower(),
            "recv_related": str(bool(recv_related)).lower(),
            "register_setup_observed": "see register_sources.csv",
            "next_trace": "Need direct non-entry caller/xref export" if is_entry or "thunk" in name.lower() else "Inspect local pcode/decompile for RDX/RSI/RBP/BL provenance",
        })

    register_rows = [
        {"register_or_value":"RDX context","path_b_location":"FUN_11b59337 / FUN_11b59838","source_status":"unknown","evidence_summary":"FUN_11b59337 copies RDX into RBP; FUN_11b59838 tests EDX before dispatcher, but current exports do not show who supplies RDX.","packet_decode_implication":"RDX remains the main context blocker.","next_step":"Export direct callers/xrefs to FUN_11b45846, FUN_11b56999, FUN_11b59337, FUN_11b59832, and FUN_11b59838."},
        {"register_or_value":"RSI base","path_b_location":"dispatcher FUN_11b5625b","source_status":"unknown","evidence_summary":"Path B functions currently exported do not assign RSI before dispatcher entry.","packet_decode_implication":"Cannot compute opcode byte address.","next_step":"Need caller preserving or setting RSI before entry into 0x11B45846/0x11B566B4."},
        {"register_or_value":"[RBP+0] PC offset","path_b_location":"FUN_11b59337 -> dispatcher","source_status":"unknown","evidence_summary":"RBP becomes RDX in FUN_11b59337, so [RBP+0] depends on the unknown RDX context object.","packet_decode_implication":"If RDX is packet/VM context, this may be the meaningful PC offset.","next_step":"Find RDX context allocation/setup caller."},
        {"register_or_value":"initial BL/RBX","path_b_location":"FUN_11b56999 / dispatcher","source_status":"unknown","evidence_summary":"FUN_11b56999 reads BL but does not seed RBX; dispatcher later copies RSI into RBX before opcode transform.","packet_decode_implication":"Initial BL not bounded; effective BL depends on RSI after dispatcher setup.","next_step":"Resolve RSI first; then derive effective BL from RSI low byte."},
        {"register_or_value":"RBP intermediate","path_b_location":"FUN_11b56999 and FUN_11b59337","source_status":"partially mapped","evidence_summary":"FUN_11b56999 sets RBP=RDI, then FUN_11b59337 overwrites RBP=RDX.","packet_decode_implication":"RDI does not survive as final PC-offset base; RDX is decisive.","next_step":"Prioritize RDX caller provenance."},
        {"register_or_value":"RCX","path_b_location":"FUN_11b56999 / FUN_11b59337","source_status":"preserved/saved only","evidence_summary":"RCX is pushed/sampled in helper instructions; no context source is established.","packet_decode_implication":"No direct S2C decode evidence.","next_step":"Keep as secondary register in targeted caller export."},
    ]

    missing_rows = [
        {"missing_id":"P631-MISS-001","needed_export":"xrefs/callers to 0x11B52CE5 and 0x11B45846 beyond 0x1195D94A","reason":"0x1195D94A is only an entry/thunk JMP in current exports; real non-entry caller not found.","exact_target":"0x11B52CE5,0x11B45846","priority":"high"},
        {"missing_id":"P631-MISS-002","needed_export":"direct callers and pcode/decompile for FUN_11b56999/FUN_11b59337/FUN_11b59832/FUN_11b59838","reason":"Current chain shows RBP=RDX and EDX test, but not RDX source.","exact_target":"0x11B56999,0x11B59337,0x11B59832,0x11B59838","priority":"high"},
        {"missing_id":"P631-MISS-003","needed_export":"recv/WSARecv import callers connected to Path B graph","reason":"Current import refs are external/IAT only and not connected to function callers in available export.","exact_target":"recv,WSARecv,recvfrom callers and wrappers","priority":"high"},
        {"missing_id":"P631-MISS-004","needed_export":"one-level callers/callees around any non-entry Path B caller","reason":"Need register setup for RDX, RSI, RBX/BL, RBP, RCX at Path B entry.","exact_target":"caller-discovered functions from P631-MISS-001/002","priority":"high"},
    ]

    trace_rows = [{
        "trace_id":"P631-TRACE-001",
        "path":"Path B dispatcher entry",
        "input_requirements_available":"false",
        "bounded_vm_trace_run":"false",
        "valid_trace_candidate":"false",
        "blocker":"RDX context, RSI base, [RBP+0] PC offset, and initial/effective BL are not concrete in existing exports.",
        "next_validation_step":"Run targeted Ghidra xref export, then inspect any non-entry caller for register setup before using Pass627."
    }]

    write_csv(art / "pass631_codex_path_b_callers.csv", ["caller_id","function_or_address","role","incoming_path_b_edges","outgoing_path_b_edges","entry_or_thunk_only","recv_related","register_setup_observed","next_trace"], caller_rows)
    write_csv(art / "pass631_codex_register_sources.csv", ["register_or_value","path_b_location","source_status","evidence_summary","packet_decode_implication","next_step"], register_rows)
    write_csv(art / "pass631_codex_missing_exports.csv", ["missing_id","needed_export","reason","exact_target","priority"], missing_rows)
    write_csv(art / "pass631_codex_vm_trace_validation.csv", ["trace_id","path","input_requirements_available","bounded_vm_trace_run","valid_trace_candidate","blocker","next_validation_step"], trace_rows)

    decision = {
        "worker":"codex",
        "phase":"pass631_path_b_xref_trace",
        "path_b_reviewed": True,
        "callers_reviewed": len(caller_rows),
        "real_non_entry_caller_found": False,
        "recv_related_caller_found": False,
        "rdx_context_source_found": False,
        "rsi_base_found": False,
        "pc_offset_found": False,
        "initial_bl_found": False,
        "targeted_exports_created": True,
        "bounded_vm_trace_run": False,
        "valid_trace_candidates": 0,
        "s2c_initial_key_found": False,
        "s2c_key_derivation_path_found": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason":"Existing exports show Path B internals and entry/thunk edges, but no real non-entry caller or recv-related caller that supplies RDX/RSI/RBP/BL. RDX remains decisive because FUN_11b59337 copies RDX into RBP and dispatcher [RBP+0] depends on it.",
        "next_action":"Run tools/pass631_codex_path_b_xref_trace/export_path_b_xrefs.py in Ghidra to export direct xrefs/callers around 0x11B52CE5, 0x11B45846, 0x11B56999, 0x11B59337, 0x11B59832, 0x11B59838, plus recv/WSARecv wrappers."
    }
    (art / "pass631_codex_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    summary = """# Pass631 Codex Path B Xref Summary

Path B remains the only primary S2C receive/decode candidate:

`FUN_11b45846 -> FUN_11b566dd/0x11B566B4 -> FUN_11b56999 -> thunk_FUN_11b59337 -> FUN_11b59337 -> FUN_11b59832/FUN_11b59838 -> FUN_11b5625b`

## Existing Export Findings

- `0x1195D94A` is only a JMP into `0x11B52CE5`; it is not a meaningful caller.
- `0x11B52CE5` is only a thunk to `FUN_11b45846`.
- `FUN_11b45846` is a branch/thunk-like wrapper into `FUN_11b566dd` and embedded `0x11B566B4`.
- `FUN_11b56999` saves volatile registers and sets `RBP = RDI`, but this does not survive.
- `FUN_11b59337` overwrites `RBP = RDX`.
- `FUN_11b59838` prepares dispatcher scratch stack and tests `EDX` before `FUN_11b5625b`.

## Register State

The decisive missing value is `RDX`: Path B turns it into `RBP`, so dispatcher `[RBP+0]` depends on the unknown RDX context. Existing exports do not establish `RSI`, `RDX`, initial `RBX/BL`, or a recv/session context.

## Targeted Export Created

Created `tools/pass631_codex_path_b_xref_trace/` with a Ghidra exporter and offline inspector. The exporter targets xrefs/callers for Path B addresses and import callers around `recv`/`WSARecv` without broad scanning.

## VM Trace

No bounded Pass627 VM trace was run because the dispatcher tuple is not concrete.
"""
    (art / "pass631_codex_path_b_xref_summary.md").write_text(summary, encoding="utf-8")

    report = """# Codex Report - Pass631 Path B Xref Trace

Reviewed existing local Path B exports only and created targeted xref tooling.

Result: no real non-entry caller found in current exports. `0x1195D94A` and `0x11B52CE5` are entry/thunk jumps. Path B internals show `RBP` becomes `RDX`, so `[RBP+0]` depends on unknown RDX context. No recv-related caller is connected in current export tables.

No bounded VM trace was run. Next action is the targeted Ghidra export for Path B xrefs and recv/WSARecv wrapper linkage.
"""
    (repo / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
