"""Pass622 deep static material inventory and S2C trace.

This pass inventories real static material and emits Git-safe evidence. It does
not read PCAP payloads, does not run target binaries, and avoids committing raw
binary bytes or decrypted data.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
ARTIFACTS = REPO / "artifacts"

ROOTS = [Path(r"C:\AionTools"), PRIVATE, REPO]
EXTS = {".txt", ".csv", ".json", ".md", ".py", ".java", ".asm", ".c", ".cpp", ".h", ".log"}
SKIP_PARTS = {".git", "__pycache__", "site-packages", "compiled-bundles", "ghidra_appdata", "ghidra_localappdata"}
TERMS = [
    "pcode", "disassembly", "decompile", "Ghidra", "pass8b", "handler", "dispatcher", "flow", "xrefs", "VM", ".aion1", "EA_VM", "TargetDump",
    "0x11B562BD", "11B562BD", "11b562bd", "0x11B5630F", "11B5630F", "11b5630f", "0x11B5932F", "11B5932F", "11b5932f",
    "0x11B57796", "11B57796", "11b57796", "0x11B55DF6", "11B55DF6", "11b55df6", "0x11B54E6F", "11B54E6F", "11b54e6f",
    "0x11B566B4", "11B566B4", "11b566b4", "0x11B56C63", "11B56C63", "11b56c63",
    "recv", "WSARecv", "receive", "handshake", "SM_KEY", "7785", "2106", "send", "WSASend", "socket", "key",
]
RAW_BYTES_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}\s+){4,}[0-9A-Fa-f]{2}\b")

PRIMARY_EXPORTS = [
    PRIVATE / "inbox" / "pass8b_target_disassembly.txt",
    PRIVATE / "inbox" / "pass8b_target_pcode.txt",
    PRIVATE / "inbox" / "pass8b_target_flows.csv",
    PRIVATE / "inbox" / "pass8b_handler_table_from_ghidra.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_target_disassembly.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_target_pcode.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_target_flows.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_handler_table_from_ghidra.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_recursive_flow_disassembly.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_recursive_flow_pcode.txt",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_flow_graph.csv",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_interesting_state_instructions.csv",
    Path(r"C:\AionTools\EA_VM_TargetDumpJava.java"),
    Path(r"C:\AionTools\EA_VM_FlowDumpJava.java"),
    Path(r"C:\AionTools\euroaion\game.dll.txt"),
]


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() not in EXTS:
        return False
    parts = {p.lower() for p in path.parts}
    return not (parts & SKIP_PARTS)


def iter_material() -> list[Path]:
    seen: set[str] = set()
    found: list[Path] = []
    for root in ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or not is_text_file(path):
                continue
            name = path.name.lower()
            key_str = str(path).lower()
            if any(t.lower() in name or t.lower() in key_str for t in TERMS):
                k = str(path.resolve()).lower()
                if k not in seen:
                    seen.add(k)
                    found.append(path)
    for path in PRIMARY_EXPORTS:
        if path.exists() and path.is_file():
            k = str(path.resolve()).lower()
            if k not in seen:
                seen.add(k)
                found.append(path)
    return sorted(found, key=lambda p: (0 if p in PRIMARY_EXPORTS else 1, str(p).lower()))


def scan_terms(path: Path, max_bytes: int = 12_000_000) -> list[str]:
    size = path.stat().st_size
    found: list[str] = []
    # The giant IDA dump is too large/noisy for full regex scanning here; targeted
    # manual Select-String showed 7785/2106 as address false positives.
    if size > max_bytes:
        if path.name.lower() == "game.dll.txt":
            return ["large-static-dump", "7785_false_positive_addresses", "2106_false_positive_addresses"]
        return ["large-static-file-not-content-scanned"]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    low = text.lower()
    for term in TERMS:
        if term.lower() in low:
            found.append(term)
    return sorted(set(found), key=str.lower)


def relevance(path: Path, terms: list[str]) -> tuple[str, str, str]:
    n = path.name.lower()
    if n.startswith("pass8b_target_pcode") or n.startswith("pass8b_target_disassembly") or n.startswith("pass8b_target_flows"):
        return "high", "real_static_export", "primary Ghidra Pass8B dispatcher/handler export; traceable pcode/disassembly/flow"
    if n.startswith("pass8c_recursive") or n.startswith("pass8c_flow") or n.startswith("pass8c_interesting"):
        return "high", "real_static_export", "recursive VM launch/dispatcher flow export"
    if "handler_table" in n:
        return "high", "real_static_export", "VM opcode-to-handler table with requested handler addresses"
    if n in {"ea_vm_targetdumpjava.java", "ea_vm_flowdumpjava.java"}:
        return "medium", "export_tool", "Ghidra Java exporter script with concrete dispatcher/handler ranges"
    if n == "game.dll.txt":
        return "medium", "large_static_dump", "huge IDA-style dump; targeted network-term scan produced address false positives, not recv path proof"
    if terms:
        return "medium", "supporting_static_text", "contains requested static trace terms"
    return "low", "supporting_text", "matched filename/path only"


def build_inventory() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in iter_material():
        terms = scan_terms(path)
        rel, kind, reason = relevance(path, terms)
        next_action = "use in trace" if rel == "high" else ("request focused export/xrefs" if path.name.lower() == "game.dll.txt" else "orientation only")
        rows.append({
            "path": str(path),
            "file_size": str(path.stat().st_size),
            "matched_terms": ";".join(terms),
            "relevance": rel,
            "reason": f"{kind}: {reason}",
            "next_action": next_action,
        })
    return rows


def write_csv(path: Path, rows: list[dict[str, str]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def sanitize(line: str) -> str:
    return RAW_BYTES_RE.sub("[bytes-redacted]", line.strip())[:240]


def find_line(path: Path, terms: list[str]) -> list[tuple[int, str, str]]:
    if not path.exists() or path.stat().st_size > 20_000_000:
        return []
    out: list[tuple[int, str, str]] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines, 1):
        low = line.lower()
        for term in terms:
            if term.lower() in low:
                out.append((i, term, sanitize(line)))
                break
    return out


def build_candidates() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    def add(src: Path, loc: str, addr: str, etype: str, role: str, conf: str, next_test: str) -> None:
        rows.append({
            "candidate_id": f"P622-{len(rows)+1:03d}",
            "source_file": str(src),
            "location": loc,
            "address_or_symbol": addr,
            "evidence_type": etype,
            "possible_role": role,
            "confidence": conf,
            "next_test": next_test,
        })
    for src in PRIMARY_EXPORTS:
        if not src.exists():
            continue
        for lineno, term, line in find_line(src, ["11b566b4", "11b56c63", "11b562bd", "11b5630f", "11b57796", "11b5932f", "11b55df6", "11b54e6f"]):
            tl = term.lower()
            if tl in {"11b566b4", "11b56c63"}:
                add(src, str(lineno), "0x" + term.upper(), "VM_dispatch_path", "VM launch entry/TLS entry anchor; useful as xref target for native caller discovery", "high", "export xrefs/callers to this address and caller pcode")
            elif tl == "11b562bd":
                add(src, str(lineno), "0x11B562BD", "VM_dispatch_path", "dispatcher bytecode fetch from RSI; confirms VM stream, not packet buffer", "high", "export caller/context setup that initializes RSI/RBP before this dispatcher")
            elif tl == "11b5630f":
                add(src, str(lineno), "0x11B5630F", "VM_dispatch_path", "handler table lookup via R12+RAX*8", "high", "export decoded VM bytecode sequence or native caller xrefs")
            elif tl == "11b57796":
                add(src, str(lineno), "0x11B57796", "real_static_export", "handler reads VM operand from RSI and rejoins dispatcher; no recv/key write proven", "medium", "trace only if real handshake VM bytecode reaches this handler")
            elif tl == "11b5932f":
                add(src, str(lineno), "0x11B5932F", "real_static_export", "handler table/SETZ class candidate; no recv/key write proven", "medium", "trace only if real handshake VM bytecode reaches this handler")
            elif tl == "11b55df6":
                add(src, str(lineno), "0x11B55DF6", "real_static_export", "handler table candidate requested by task; currently unconnected to recv/S2C key path", "low", "needs VM bytecode/caller connection")
            elif tl == "11b54e6f":
                add(src, str(lineno), "0x11B54E6F", "VM_dispatch_path", "handler table base", "high", "export xrefs/data refs and dispatcher caller context")
        for lineno, term, line in find_line(src, ["recv", "WSARecv", "receive", "SM_KEY", "handshake", "7785", "2106", "server-to-client", "S2C"]):
            # In current real exports, these are mostly exporter/script comments; keep as low unless primary dump gives a real symbol.
            add(src, str(lineno), term, "recv_path_candidate", "text occurrence of receive/handshake/network term in static material; not yet a native path proof", "low", "validate with xrefs/import table export")
    # Concrete blocker row, because current exports lack native recv caller path.
    add(Path("missing_export"), "n/a", "xrefs_to_0x11B566B4_0x11B56C63_and_WS2_32_recv", "missing_export_blocker", "need native receive/world-handshake caller slice that bridges network packet parse to VM context and S2C key slot write", "high", "generate targeted Ghidra xrefs/pcode export requested in exact_missing_exports.md")
    return rows


def write_notes(candidates: list[dict[str, str]], inventory: list[dict[str, str]]) -> None:
    high_exports = [r for r in inventory if r["relevance"] == "high"]
    notes = f"""# Pass622 Codex Deep S2C Static Trace Notes\n\n## What Advanced Beyond Pass621\n\nThis pass inventoried text/static material directly and identified the actual high-value exports instead of relying on Pass616-Pass620 summaries. It also inspected the large `C:\\AionTools\\euroaion\\game.dll.txt` dump; targeted network/port searches there surfaced address-substring false positives, not a receive path.\n\n## Real Static Exports\n\n- High-relevance exports found: `{len(high_exports)}`\n- Key concrete files: `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, `pass8b_handler_table_from_ghidra.csv`, and Pass8C recursive flow outputs.\n- Export scripts available: `EA_VM_TargetDumpJava.java` and `EA_VM_FlowDumpJava.java`.\n\n## Trace Findings\n\n- VM launch anchors are known: `0x11B566B4` and `0x11B56C63`.\n- Dispatcher anchors are known: `0x11B562BD` bytecode fetch from `RSI`, `0x11B5630F` handler-table lookup via `R12 + RAX*8`, table base `0x11B54E6F`.\n- Handler candidates `0x11B57796`, `0x11B5932F`, and `0x11B55DF6` exist in real exports/table material.\n- No current export contains the native 7785 receive/world-handshake path, direction split, or concrete write into an S2C 8-byte rolling-key slot.\n\n## Result\n\nNo S2C initial key candidate was found. No bounded validation was run. The next required artifact is exact and address-targeted; see `pass622_codex_exact_missing_exports.md`.\n"""
    (ARTIFACTS / "pass622_codex_s2c_static_trace_notes.md").write_text(notes, encoding="utf-8")


def write_missing_export() -> None:
    md = """# Pass622 Exact Missing Static Exports\n\n## Required Tool/File\n\nCreate a new Ghidra Java exporter, for example `EA_VM_RecvHandshakeXrefsJava.java`, and run it against the same static `game.dll` sample used for Pass8B/Pass8C. Output should stay local first, then commit only sanitized summaries.\n\n## Exact Export Targets\n\n1. Xrefs/callers to VM launch and dispatcher anchors:\n   - `0x11B566B4` entry launch start\n   - `0x11B56C63` TLS/alternate launch start\n   - `0x11B562BD` dispatcher byte fetch from `[RSI]`\n   - `0x11B5630F` handler table lookup\n   - `0x11B54E6F` handler table base\n\n2. Xrefs/callers/dataflow around candidate handlers only if reached by a real caller/bytecode path:\n   - `0x11B57796`\n   - `0x11B5932F`\n   - `0x11B55DF6`\n\n3. Native networking/import caller slices:\n   - imports or thunk xrefs for `WS2_32.recv`, `WSARecv`, `recvfrom`, `WSASend`, `send`, `connect`, `select`, `ioctlsocket`\n   - p-code/disassembly for each caller that feeds data into packet decode/VM launch\n   - any functions comparing or storing ports `7785` or `2106` as immediate values, but filter out address-substring false positives from `game.dll.txt`\n\n4. Context/key-slot writes:\n   - all `STORE`/`MOV [base+offset]` writes in caller slices where the base register is a packet/session/context pointer\n   - 8-byte stores or two adjacent 4-byte stores near receive/decode setup\n   - direction switch selecting send-key vs recv-key or separate C2S/S2C key slots\n\n## Why This Should Reveal S2C Key Setup\n\nCurrent Pass8B/Pass8C exports prove the VM dispatcher and handler table, but they begin inside VM launch/dispatcher code. They do not show who initializes `RSI`, `RBP`, `R12`, or `R13`, nor do they show the native receive/world-handshake parser. The S2C initial key must be assigned before S2C packet decode; therefore the missing bridge is either a native receive-path caller that initializes VM context from a server handshake packet, or a VM bytecode slice reached from that caller that writes an 8-byte receive key state.\n\n## Validation After Export\n\n1. Parse the new xref/flow export.\n2. Identify a concrete write to an 8-byte S2C key slot or a derivation formula from server seed bytes.\n3. If a concrete initial key/derivation rule emerges, run one bounded S2C validation only on Pass618 S2C frames, reporting frame number, header-valid boolean, opcode candidate, and first divergence frame.\n4. Do not commit raw packet bytes, decrypted bytes, binary bytes, or hashes.\n"""
    (ARTIFACTS / "pass622_codex_exact_missing_exports.md").write_text(md, encoding="utf-8")


def main() -> dict[str, object]:
    inventory = build_inventory()
    write_csv(ARTIFACTS / "pass622_codex_static_material_inventory.csv", inventory, ["path", "file_size", "matched_terms", "relevance", "reason", "next_action"])
    candidates = build_candidates()
    # De-duplicate repetitive mirrored inbox/outbox hits while preserving evidence breadth.
    seen = set()
    compact = []
    for row in candidates:
        key = (row["address_or_symbol"], row["evidence_type"], row["possible_role"], Path(row["source_file"]).name)
        if key in seen:
            continue
        seen.add(key)
        compact.append(row)
    write_csv(ARTIFACTS / "pass622_codex_s2c_static_candidates.csv", compact, ["candidate_id", "source_file", "location", "address_or_symbol", "evidence_type", "possible_role", "confidence", "next_test"])
    write_notes(compact, inventory)
    write_missing_export()
    best = next((r for r in compact if r["evidence_type"] == "missing_export_blocker"), compact[0] if compact else {"candidate_id": "none"})
    decision = {
        "worker": "codex",
        "phase": "pass622_deep_s2c_static_trace",
        "real_static_exports_found": True,
        "static_exports_count": len(inventory),
        "s2c_initial_key_found": False,
        "s2c_key_write_path_found": False,
        "recv_handshake_path_found": False,
        "best_candidate_id": best["candidate_id"],
        "exact_missing_export_written": True,
        "bounded_s2c_validation_run": False,
        "s2c_decoder_success": False,
        "c2s_tools_modified": False,
        "sonnet_files_modified": False,
        "antigravity_files_modified": False,
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Deep static material inventory found real Pass8B/Pass8C Ghidra exports and VM dispatcher/handler anchors, but those exports begin inside VM launch/dispatcher code and do not include native 7785 receive/world-handshake caller slices or S2C key-slot writes.",
        "next_action": "Generate EA_VM_RecvHandshakeXrefsJava export for xrefs/callers to 0x11B566B4, 0x11B56C63, 0x11B562BD, 0x11B5630F, 0x11B54E6F and WS2_32 receive/send import callers, then trace 8-byte recv key writes.",
    }
    (ARTIFACTS / "pass622_codex_s2c_static_trace_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    report = f"""# Codex Report - Pass622 Deep S2C Static Trace\n\n- Real static exports found: true\n- Static material inventory rows: {len(inventory)}\n- S2C initial key found: false\n- S2C key write path found: false\n- Receive/world-handshake path found: false\n- Best candidate: {best['candidate_id']}\n- Exact missing export written: true\n- Bounded validation run: false\n- S2C decoder success: false\n- Next action: {decision['next_action']}\n- Safety: no C2S tool changes, no Sonnet/Antigravity file changes, no raw packet/decrypted/binary data committed.\n"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
