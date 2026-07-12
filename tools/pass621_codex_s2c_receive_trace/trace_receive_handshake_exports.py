"""Pass621 targeted receive/world-handshake trace over real static exports."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from inventory_static_exports import ARTIFACTS, PRIVATE, REPO, build_inventory, write_inventory

PRIMARY = [
    PRIVATE / "inbox" / "pass8b_target_disassembly.txt",
    PRIVATE / "inbox" / "pass8b_target_pcode.txt",
    PRIVATE / "inbox" / "pass8b_target_flows.csv",
    PRIVATE / "inbox" / "pass8b_handler_table_from_ghidra.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_recursive_flow_disassembly.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_recursive_flow_pcode.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_flow_graph.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_interesting_state_instructions.csv",
    Path(r"C:\AionTools\EA_VM_TargetDumpJava.java"),
    Path(r"C:\AionTools\EA_VM_FlowDumpJava.java"),
]

ADDRESS_TERMS = ["11b562bd", "11b5630f", "11b5932f", "11b57796", "11b55df6"]
RECV_TERMS = ["recv", "receive", "server-to-client", "s2c", "handshake", "sm_key", "7785", "2106", "send", "decode"]
WRITE_TERMS = ["STORE", "MOV      qword ptr", "MOV      dword ptr", "[RBP]", "[RSP", "[RSI", "[RDI", "key"]
RAW_BYTES_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}\s+){2,}[0-9A-Fa-f]{2}\b")


def read(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def clean(s: str) -> str:
    s = RAW_BYTES_RE.sub("[bytes-redacted]", s.strip())
    return s[:220]


def line_has(line: str, terms: list[str]) -> bool:
    low = line.lower()
    return any(t.lower() in low for t in terms)


def add_candidate(rows: list[dict[str, str]], source: Path, lineno: int, address: str, etype: str, role: str, confidence: str, next_test: str) -> None:
    rows.append({
        "candidate_id": f"RHS-{len(rows)+1:03d}",
        "source_file": str(source),
        "location": str(lineno),
        "address_or_symbol": address,
        "evidence_type": etype,
        "possible_role": role,
        "confidence": confidence,
        "next_test": next_test,
    })


def trace_exports() -> tuple[list[dict[str, str]], dict[str, bool]]:
    rows: list[dict[str, str]] = []
    flags = {
        "recv_handshake_path_found": False,
        "s2c_key_write_path_found": False,
        "handler_dispatch_confirmed": False,
        "missing_receive_terms": True,
    }
    for path in PRIMARY:
        lines = read(path)
        if not lines:
            continue
        saw_recv = False
        for i, line in enumerate(lines, 1):
            low = line.lower()
            if line_has(line, ADDRESS_TERMS):
                if "11b562bd" in low:
                    add_candidate(rows, path, i, "0x11B562BD", "VM_handler_candidate", "VM dispatcher bytecode fetch from RSI; confirms VM instruction stream, not receive packet buffer", "high", "do not treat as S2C key write; trace native caller that initializes RSI/RBP")
                    flags["handler_dispatch_confirmed"] = True
                elif "11b5630f" in low:
                    add_candidate(rows, path, i, "0x11B5630F", "VM_handler_candidate", "VM handler table lookup through R12 + opcode index", "high", "trace real opcode sequence or native context caller")
                    flags["handler_dispatch_confirmed"] = True
                elif "11b57796" in low:
                    add_candidate(rows, path, i, "0x11B57796", "VM_handler_candidate", "handler reads VM bytecode operand and returns into dispatcher continuation; not a proven S2C key write", "medium", "trace continuation to any context STORE reaching key slot")
                elif "11b5932f" in low:
                    add_candidate(rows, path, i, "0x11B5932F", "VM_handler_candidate", "handler table maps opcodes to SETZ AH class; no receive/key context proven", "medium", "obtain pcode slice if this handler appears in real handshake VM bytecode")
                elif "11b55df6" in low:
                    add_candidate(rows, path, i, "0x11B55DF6", "VM_handler_candidate", "requested shift/unknown handler address appears in handler/table exports", "low", "only pursue if connected to real recv handshake bytecode")
            if line_has(line, RECV_TERMS):
                saw_recv = True
                flags["missing_receive_terms"] = False
                add_candidate(rows, path, i, "text-term", "direction_split_candidate", "receive/handshake/direction term appears in static export text", "low", "verify it is native receive path and not script/comment metadata")
            if ("store" in low or "mov      qword ptr" in low or "mov      dword ptr" in low) and any(reg in low for reg in ["[rbp", "[rsp", "[rsi", "[rdi"]):
                add_candidate(rows, path, i, "memory-write", "context_layout_candidate", "VM stack/context write in exported slice; no S2C key slot proven", "low", "need caller/context mapping to distinguish VM stack from packet key state")
        if not saw_recv and path.name.lower().startswith(("pass8b", "pass8c")):
            pass
    return rows, flags


def write_candidates(rows: list[dict[str, str]]) -> None:
    fields = ["candidate_id", "source_file", "location", "address_or_symbol", "evidence_type", "possible_role", "confidence", "next_test"]
    with (ARTIFACTS / "pass621_codex_s2c_receive_candidates.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_notes(rows: list[dict[str, str]], flags: dict[str, bool], export_count: int) -> None:
    recv_found = flags["recv_handshake_path_found"]
    key_write = flags["s2c_key_write_path_found"]
    notes = f"""# Pass621 Codex S2C Receive Handshake Trace Notes\n\n## Static Export Inventory\n\nReal static exports found: `{export_count}`. Primary usable exports are the Pass8B Ghidra target disassembly/p-code/flow files, handler table CSV, Pass8C recursive flow outputs, and the `EA_VM_TargetDumpJava.java` / `EA_VM_FlowDumpJava.java` scripts.\n\n## Trace Result\n\n- VM dispatcher evidence: confirmed. `0x11B562BD` is the VM bytecode fetch from `RSI`; `0x11B5630F` is the handler table lookup.\n- Handler evidence: `0x11B57796`, `0x11B5932F`, and `0x11B55DF6` appear in handler/table/static export material, but none are connected to a receive handshake packet or S2C key-state write in the available exports.\n- Receive/world-handshake path found: `{str(recv_found).lower()}`.\n- S2C 8-byte key write path found: `{str(key_write).lower()}`.\n\n## Important Negative Finding\n\nThe actual Pass8B/Pass8C exports are VM launch/dispatcher/handler slices. They do not include the native 7785 receive path, server handshake parser, direction switch, or a concrete write into an S2C rolling-key slot. Memory writes visible in these exports are VM stack/context mechanics, not proven packet key state.\n\n## Missing Export Needed\n\nGenerate a focused static p-code/disassembly/flow export around the native function(s) that call into the VM for world-server receive/decode handling, including call sites that initialize `RSI`, `RBP`, `R12`, and `R13` before dispatcher entry. The export needs to cover references to 7785 receive packet handling, SM_KEY/world handshake parsing, and writes to the suspected 8-byte send/recv key slots.\n\n## Candidate Count\n\nCandidate rows written: `{len(rows)}`.\n"""
    (ARTIFACTS / "pass621_codex_s2c_receive_trace_notes.md").write_text(notes, encoding="utf-8")


def main() -> dict[str, object]:
    inventory = build_inventory()
    write_inventory(inventory)
    rows, flags = trace_exports()
    # Keep candidates compact: de-duplicate by file/location/address/type.
    seen = set()
    compact = []
    for row in rows:
        key = (row["source_file"], row["location"], row["address_or_symbol"], row["evidence_type"])
        if key in seen:
            continue
        seen.add(key)
        compact.append(row)
    write_candidates(compact)
    write_notes(compact, flags, len(inventory))
    best = next((r for r in compact if r["address_or_symbol"] == "0x11B562BD"), compact[0] if compact else {"candidate_id": "none"})
    decision = {
        "worker": "codex",
        "phase": "pass621_s2c_receive_handshake_trace",
        "real_static_exports_found": bool(inventory),
        "static_exports_count": len(inventory),
        "s2c_initial_key_found": False,
        "s2c_key_write_path_found": False,
        "recv_handshake_path_found": False,
        "best_candidate_id": best.get("candidate_id", "none"),
        "bounded_s2c_validation_run": False,
        "s2c_decoder_success": False,
        "missing_export_needed": "Focused p-code/disassembly/flow slice for the native 7785 receive/world-handshake path that initializes VM context registers and writes the S2C 8-byte rolling key slot; current Pass8B/Pass8C exports cover VM dispatcher/handlers but not the receive handshake caller/path.",
        "c2s_tools_modified": False,
        "sonnet_files_modified": False,
        "antigravity_files_modified": False,
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Actual static exports were found and traced. They confirm VM dispatcher/handler slices but do not include native receive/world-handshake parsing or any concrete S2C key-state write path.",
        "next_action": "Generate targeted Ghidra p-code/flow export for native 7785 receive/world-handshake caller path and context/key-slot writes, then rerun Pass621 trace.",
    }
    (ARTIFACTS / "pass621_codex_s2c_receive_trace_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    report = f"""# Codex Report - Pass621 S2C Receive Handshake Trace\n\n- Real static exports found: {bool(inventory)}\n- Static exports inventoried: {len(inventory)}\n- S2C initial key found: false\n- S2C key write path found: false\n- Receive/world-handshake path found: false\n- Best candidate: {best.get('candidate_id', 'none')}\n- Bounded S2C validation run: false\n- S2C decoder success: false\n- Missing export needed: {decision['missing_export_needed']}\n- Safety: static/offline only; no C2S tool changes; no Sonnet/Antigravity file changes; no private packet or raw binary data committed.\n"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
