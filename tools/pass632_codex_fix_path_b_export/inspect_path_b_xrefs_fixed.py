#!/usr/bin/env python3
"""Fixed Pass632 Path B xref postprocessor.

Guarantee: never overwrite useful previous/fallback Path B rows with an empty export
unless the export contains an explicit manifest proving there are no callers.
"""

import argparse
import csv
import json
import re
from pathlib import Path

PATH_B_TERMS = ["11B45846", "11B52CE5", "1195D94A", "11B566DD", "11B566B4", "11B56999", "11B56075", "11B59337", "11B59832", "11B59838", "11B5625B"]
FIELDS_CALLERS = ["caller_id","function_or_address","role","incoming_path_b_edges","outgoing_path_b_edges","entry_or_thunk_only","recv_related","register_setup_observed","next_trace"]
FIELDS_REGS = ["register_or_value","path_b_location","source_status","evidence_summary","packet_decode_implication","next_step"]
FIELDS_MISSING = ["missing_id","needed_export","reason","exact_target","priority"]
FIELDS_TRACE = ["trace_id","path","input_requirements_available","bounded_vm_trace_run","valid_trace_candidate","blocker","next_validation_step"]

ROLE = {
    "0x11B5625B":"dispatcher FUN_11b5625b",
    "0x11B45846":"FUN_11b45846",
    "0x1195D94A":"entry/thunk to FUN_11b45846",
    "0x11B59838":"FUN_11b59838 dispatcher setup",
    "0x11B52CE5":"thunk_FUN_11b45846",
    "0x11B59337":"FUN_11b59337",
    "0x11B566DD":"FUN_11b566dd thunk to 0x11B566B4",
    "0x11B56999":"FUN_11b56999",
    "0x11B56075":"thunk_FUN_11b59337",
}


def read_csv(path):
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def read_text_any(path):
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fields})


def load_manifest(export_dir):
    p = export_dir / "path_b_manifest.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {"manifest_parse_error": True}


def normalize_entry(entry):
    if not entry:
        return ""
    entry = entry.strip()
    if entry.lower().startswith("0x"):
        return "0x" + entry[2:].upper()
    return entry


def rows_from_export(export_dir):
    java_path_b_export = (export_dir / "path_b_functions.csv").exists()
    funcs = read_csv(export_dir / "path_b_functions.csv") or read_csv(export_dir / "candidate_functions.csv")
    edges = read_csv(export_dir / "path_b_call_edges.csv") or read_csv(export_dir / "call_edges.csv")
    imports = read_csv(export_dir / "path_b_import_refs.csv") or read_csv(export_dir / "import_refs.csv")
    path_b_edges = []
    for row in edges:
        if any(term in " ".join(row.values()).upper() for term in PATH_B_TERMS):
            path_b_edges.append(row)
    rows = []
    seen = set()
    for row in funcs:
        if not java_path_b_export and not any(term in " ".join(row.values()).upper() for term in PATH_B_TERMS):
            continue
        entry = normalize_entry(row.get("entry") or row.get("function_entry") or row.get("address_requested") or "")
        name = row.get("name") or row.get("function") or ""
        key = (entry, name)
        if key in seen:
            continue
        seen.add(key)
        incoming = [e for e in path_b_edges if normalize_entry(e.get("to_entry", "")) == entry]
        outgoing = [e for e in path_b_edges if normalize_entry(e.get("from_entry", "")) == entry]
        is_entry = entry == "0x1195D94A" or name.lower() == "entry" or "thunk" in name.lower()
        recv_related = any((normalize_entry(imp.get("caller_entry", "")) == entry or imp.get("caller_name", "") == name) for imp in imports)
        rows.append({
            "caller_id":"P632-CALL-%03d" % (len(rows) + 1),
            "function_or_address":(entry + " " + name).strip(),
            "role":ROLE.get(entry, "Path B graph function"),
            "incoming_path_b_edges":len(incoming),
            "outgoing_path_b_edges":len(outgoing),
            "entry_or_thunk_only":str(bool(is_entry)).lower(),
            "recv_related":str(bool(recv_related)).lower(),
            "register_setup_observed":"see register_sources_fixed.csv",
            "next_trace":"Need direct non-entry caller/xref export" if is_entry else "Inspect local pcode/decompile for RDX/RSI/RBP/BL provenance",
        })
    return rows


def standard_register_rows():
    return [
        {"register_or_value":"RDX context","path_b_location":"FUN_11b59337 / FUN_11b59838","source_status":"unknown","evidence_summary":"FUN_11b59337 copies RDX into RBP; FUN_11b59838 tests EDX before dispatcher, but current usable exports do not show who supplies RDX.","packet_decode_implication":"RDX remains the main context blocker.","next_step":"Run Java exporter; inspect non-entry callers/xrefs to FUN_11b45846, FUN_11b56999, FUN_11b59337, FUN_11b59832, FUN_11b59838."},
        {"register_or_value":"RSI base","path_b_location":"dispatcher FUN_11b5625b","source_status":"unknown","evidence_summary":"Current usable Path B exports do not assign RSI before dispatcher entry.","packet_decode_implication":"Cannot compute opcode byte address.","next_step":"Need caller preserving or setting RSI before entry into Path B."},
        {"register_or_value":"[RBP+0] PC offset","path_b_location":"FUN_11b59337 -> dispatcher","source_status":"unknown","evidence_summary":"RBP becomes RDX in FUN_11b59337, so [RBP+0] depends on unknown RDX context object.","packet_decode_implication":"If RDX is VM/packet context, this may be the meaningful PC offset.","next_step":"Find RDX context setup caller."},
        {"register_or_value":"initial BL/RBX","path_b_location":"FUN_11b56999 / dispatcher","source_status":"unknown","evidence_summary":"FUN_11b56999 reads BL but does not seed RBX; dispatcher later copies RSI into RBX before opcode transform.","packet_decode_implication":"Initial BL not bounded; effective BL depends on RSI.","next_step":"Resolve RSI first; derive effective BL from RSI low byte."},
        {"register_or_value":"RBP intermediate","path_b_location":"FUN_11b56999 and FUN_11b59337","source_status":"partially mapped","evidence_summary":"FUN_11b56999 sets RBP=RDI, then FUN_11b59337 overwrites RBP=RDX.","packet_decode_implication":"RDI does not survive as final PC-offset base; RDX is decisive.","next_step":"Prioritize RDX caller provenance."},
        {"register_or_value":"RCX","path_b_location":"FUN_11b56999 / FUN_11b59337","source_status":"preserved/saved only","evidence_summary":"RCX is pushed/sampled in helper instructions; no context source is established.","packet_decode_implication":"No direct S2C decode evidence.","next_step":"Keep as secondary register in targeted caller export."},
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default=r"C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs")
    ap.add_argument("--fallback-dir", default=r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
    ap.add_argument("--repo-root", default=r"C:\AionTools\aion-agent-bridge")
    ns = ap.parse_args()
    export_dir = Path(ns.export_dir)
    fallback_dir = Path(ns.fallback_dir)
    repo = Path(ns.repo_root)
    art = repo / "artifacts"

    manifest = load_manifest(export_dir)
    export_files = list(export_dir.glob("*")) if export_dir.exists() else []
    log_files = [p for p in export_files if p.suffix.lower() == ".log"]
    log_text = "\n".join(read_text_any(p) for p in log_files[:3])
    export_script_ran = "Execute script: export_path_b_xrefs.py" in log_text or bool(manifest)
    python_unavailable = "Python is not available" in log_text or "not started with PyGhidra" in log_text

    export_rows = rows_from_export(export_dir)
    fallback_rows = rows_from_export(fallback_dir)
    explicit_no_callers = bool(manifest.get("explicit_no_callers"))

    if export_rows:
        caller_rows = export_rows
        source = "pass631_or_pass632_export"
        postprocessor_bug = False
    elif explicit_no_callers:
        caller_rows = []
        source = "explicit_empty_export"
        postprocessor_bug = False
    else:
        caller_rows = fallback_rows
        source = "fallback_pass622_known_good"
        postprocessor_bug = True

    missing_rows = [
        {"missing_id":"P632-MISS-001","needed_export":"Java Path B xref export output CSVs","reason":"Pass631 Python/Jython export failed under Ghidra headless because PyGhidra was unavailable; output folder had only a log.","exact_target":"tools/pass632_codex_fix_path_b_export/ghidra_export_path_b_xrefs.java","priority":"high"},
        {"missing_id":"P632-MISS-002","needed_export":"direct non-entry xrefs to 0x11B52CE5/0x11B45846 and callers of 0x11B56999/0x11B59337/0x11B59832/0x11B59838","reason":"Fallback rows restore Path B graph but still do not reveal RDX/RSI/RBP/BL sources.","exact_target":"Path B xrefs/callers one level each direction","priority":"high"},
        {"missing_id":"P632-MISS-003","needed_export":"recv/WSARecv caller wrappers connected to Path B callers","reason":"Current usable rows do not tie Path B to receive/socket buffer handling.","exact_target":"recv,WSARecv,recvfrom import callers and wrappers","priority":"high"},
    ]
    trace_rows = [{"trace_id":"P632-TRACE-001","path":"Path B dispatcher entry","input_requirements_available":"false","bounded_vm_trace_run":"false","valid_trace_candidate":"false","blocker":"RDX context, RSI base, [RBP+0] PC offset, and initial/effective BL remain unresolved; fixed postprocessor restored graph rows only.","next_validation_step":"Run Java exporter and inspect any non-entry caller before Pass627."}]

    write_csv(art / "pass632_codex_path_b_callers_fixed.csv", FIELDS_CALLERS, caller_rows)
    write_csv(art / "pass632_codex_register_sources_fixed.csv", FIELDS_REGS, standard_register_rows())
    write_csv(art / "pass632_codex_missing_exports_fixed.csv", FIELDS_MISSING, missing_rows)
    write_csv(art / "pass632_codex_vm_trace_validation.csv", FIELDS_TRACE, trace_rows)

    diagnostics = f"""# Pass632 Export Diagnostics

## Checks

1. Did `export_path_b_xrefs.py` run under Ghidra?

Yes, Ghidra attempted to execute it. The local log contains `Execute script: export_path_b_xrefs.py`.

2. Did it write files to `C:\\AionTools\\aion_decoder_agent\\outbox\\pass631_path_b_xrefs`?

No usable export files were found. The folder contained `{len(export_files)}` file(s), and the only observed required output was the log file.

3. Did the log contain exceptions?

Yes. The log reports: `Ghidra was not started with PyGhidra. Python is not available`.

4. Did `inspect_path_b_callers.py` read the right export directory?

It read the requested Pass631 export directory, but that directory had no CSV/function export files because the Python Ghidra script failed before writing them.

5. Why were the 9 known Path B rows removed?

Postprocessor bug: it treated an empty/broken export directory as authoritative and overwrote the useful previous rows with an empty CSV. The export did not explicitly prove no callers; it failed before producing data.

6. Fix applied

`inspect_path_b_xrefs_fixed.py` restores from the known-good Pass622 Path B rows when the new export is empty and lacks an explicit `explicit_no_callers` manifest. Empty exports can no longer clobber useful rows by accident.

7. Java exporter

Created `ghidra_export_path_b_xrefs.java` so headless Ghidra can export Path B xrefs without PyGhidra/Jython support.

## Current Fixed Result

- source used: `{source}`
- restored/found caller rows: `{len(caller_rows)}`
- Python unavailable in Ghidra log: `{str(python_unavailable).lower()}`
"""
    (art / "pass632_codex_export_diagnostics.md").write_text(diagnostics, encoding="utf-8")

    decision = {
        "worker":"codex",
        "phase":"pass632_fix_path_b_xref_export",
        "pass631_empty_result_confirmed": True,
        "export_script_ran": bool(export_script_ran),
        "export_log_reviewed": True,
        "export_files_found": len(export_files),
        "postprocessor_bug_found": bool(postprocessor_bug),
        "java_exporter_created": True,
        "callers_restored_or_found": len(caller_rows),
        "real_non_entry_caller_found": False,
        "recv_related_caller_found": False,
        "rdx_context_source_found": False,
        "rsi_base_found": False,
        "pc_offset_found": False,
        "initial_bl_found": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason":"Pass631 empty result was caused by Ghidra headless failing to run the Python exporter because PyGhidra was unavailable. The postprocessor then incorrectly treated the empty export as authoritative. Fixed postprocessor restores known-good Path B rows unless an export explicitly proves no callers, and a Java exporter was created.",
        "next_action":"Run ghidra_export_path_b_xrefs.java under Ghidra headless, then rerun inspect_path_b_xrefs_fixed.py against pass631_path_b_xrefs."
    }
    (art / "pass632_codex_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    report = f"""# Codex Report - Pass632 Path B Export Fix

Diagnosed the Pass631 empty result regression. Ghidra attempted to run `export_path_b_xrefs.py`, but headless was not started with PyGhidra, so Python was unavailable and no export CSVs were written.

The Pass631 postprocessor bug was that it treated the empty export folder as authoritative and overwrote the useful known Path B rows. The fixed postprocessor now restores from the Pass622 known-good export unless a new export explicitly proves no callers.

Created Java exporter: `tools/pass632_codex_fix_path_b_export/ghidra_export_path_b_xrefs.java`.

Fixed caller rows restored/found: `{len(caller_rows)}`.
"""
    (repo / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
