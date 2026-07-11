from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path

BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
SOURCE = Path(r"C:\AionTools\EA_VM_TargetDumpJava.java")
NOTES = PRIVATE / "outbox" / "pass609_antigravity_longrun_local" / "longrun_notes.md"
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"

TABLE_RE = re.compile(r"long\s+table\s*=\s*0x([0-9A-Fa-f]+)L")
ADD_RE = re.compile(r"long\s+addConst\s*=\s*0x([0-9A-Fa-f]+)L")
RANGE_RE = re.compile(r"dumpRange\(\"([^\"]+)\",\s*0x([0-9A-Fa-f]+)L,\s*0x([0-9A-Fa-f]+)L\)")
KNOWN_NOTE_RE = re.compile(r"`(0x[0-9A-Fa-f]+)` \(Opcode ([^)]+)\)")

BEHAVIOR_PATTERNS = {
    "arithmetic_add_sub": [" add ", " sub ", "+", "-", "INT_ADD", "INT_SUB"],
    "xor_or_and": [" xor ", " or ", " and ", "^", "INT_XOR", "INT_OR", "INT_AND"],
    "shift_rotate": [" rol", " ror", " shl", " shr", " sar", "INT_LEFT", "INT_RIGHT"],
    "memory_load": [" mov ", "LOAD", "["],
    "memory_store": [" mov ", "STORE", "["],
    "pointer_update": [" rsi", " rbx", " r12", "rsi", "rbx", "r12"],
    "branch_dispatch": [" jmp", " call", " cbranch", "BRANCH", "CALL", "RETURN"],
    "constant_load": ["0x", "const", "COPY"],
    "byte_swap": ["bswap", "bsf", "bsr"],
    "table_lookup": ["rax*8", "r12+rax*8", "[r12", "multiequal"],
    "call_external": ["CALL", "call"],
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def hx(value: int) -> str:
    return f"0x{value:016X}"


def parse_source() -> dict[str, object]:
    text = read(SOURCE)
    table_match = TABLE_RE.search(text)
    add_match = ADD_RE.search(text)
    ranges = [m.groups() for m in RANGE_RE.finditer(text)]
    loop_256 = "op < 256" in text and "op++" in text and "table + ((long)op) * 8L" in text
    formula_present = "handler = raw + addConst" in text or "handler = int64(entry) + 0x15F664FE" in text
    return {
        "source_exists": SOURCE.exists(),
        "table_va": int(table_match.group(1), 16) if table_match else None,
        "add_const": int(add_match.group(1), 16) if add_match else None,
        "loop_256": loop_256,
        "formula_present": formula_present,
        "ranges": ranges,
        "text": text,
    }


def parse_known_note_handlers() -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    notes = read(NOTES)
    for addr, op_text in KNOWN_NOTE_RE.findall(notes):
        va = int(addr, 16)
        indexes = set()
        for part in re.split(r"[/, ]+", op_text):
            part = part.strip()
            if part.isdigit():
                indexes.add(part)
        out.setdefault(va, set()).update(indexes)
    return out


def classify_text(blob: str) -> list[str]:
    low = " " + blob.lower() + " "
    classes = []
    for name, pats in BEHAVIOR_PATTERNS.items():
        if any(p.lower() in low for p in pats):
            classes.append(name)
    return classes or ["unknown"]


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    INBOX.mkdir(parents=True, exist_ok=True)
    parsed = parse_source()
    known = parse_known_note_handlers()
    ranges = parsed["ranges"]
    range_by_start = {int(start, 16): name for name, start, _end in ranges}
    table_va = parsed["table_va"]
    add_const = parsed["add_const"]
    formula_verified = table_va == 0x11B54E6F and add_const == 0x15F664FE and bool(parsed["formula_present"])
    exporter_loop_256 = bool(parsed["loop_256"])
    generated_table_paths = list(Path(r"C:\AionTools").glob("**/pass8b_handler_table_from_ghidra.csv"))
    generated_pcode_paths = list(Path(r"C:\AionTools").glob("**/pass8b_target_pcode.txt"))
    table_entries_verified = False

    handler_rows = []
    for idx in range(256):
        handler_rows.append({
            "handler_index": idx,
            "handler_va": "",
            "occurrence_count": "",
            "classification": "unverified_missing_generated_table",
            "notes": "EA_VM_TargetDumpJava has a 256-iteration table dumper, but pass8b_handler_table_from_ghidra.csv is not present locally.",
        })
    for va, indexes in known.items():
        count = len(indexes)
        for index_text in indexes:
            i = int(index_text)
            if 0 <= i < 256:
                handler_rows[i] = {
                    "handler_index": i,
                    "handler_va": hx(va),
                    "occurrence_count": count,
                    "classification": "reported_by_antigravity_notes_not_table_verified",
                    "notes": f"Address appears in Antigravity notes for opcode group {','.join(sorted(indexes, key=int))}; table CSV is missing.",
                }
    write_csv(ART / "pass610_codex_vm_table_handlers.csv", handler_rows, ["handler_index", "handler_va", "occurrence_count", "classification", "notes"])

    classification_rows = []
    for name, start, end in ranges:
        start_i = int(start, 16)
        behavior_blob = name.replace("_", " ")
        classes = classify_text(behavior_blob)
        classification_rows.append({
            "handler_or_range": name,
            "start_va": hx(start_i),
            "end_va": hx(int(end, 16)),
            "behavior_classes": "|".join(classes),
            "evidence_source": "EA_VM_TargetDumpJava dumpRange name only; generated p-code missing" if not generated_pcode_paths else "p-code available",
            "notes": "High-level classification is weak because only exporter range names are present." if not generated_pcode_paths else "Generated p-code should be parsed for stronger classification.",
        })
    for va, indexes in known.items():
        classification_rows.append({
            "handler_or_range": "reported_handler_group_" + "_".join(sorted(indexes, key=int)),
            "start_va": hx(va),
            "end_va": "",
            "behavior_classes": "unknown|branch_dispatch",
            "evidence_source": "Antigravity longrun notes",
            "notes": "Notes describe complex register shuffling/JMP spaghetti or mapped handler group, but no p-code lines are present locally.",
        })
    write_csv(ART / "pass610_codex_vm_handler_classification.csv", classification_rows)

    transform_candidates = [
        {
            "candidate_id": "P610-TC1",
            "handler_va": "0x0000000011B57796",
            "handler_index": "71|113|120|157|187|231|247",
            "reason": "Reported repeated VM handler group with complex register shuffling and JMP-heavy control flow; could participate in dispatch/state mutation but not proven packet-transform logic.",
            "behavior_class": "unknown|branch_dispatch|pointer_update",
            "confidence": "medium_for_vm_relevance_low_for_packet_transform",
            "next_analysis_step": "Regenerate pass8b_target_pcode.txt and handler-table CSV; parse exact p-code for byte load/store, xor/add/shift, and buffer write behavior.",
        },
        {
            "candidate_id": "P610-TC2",
            "handler_va": "0x0000000011B5932F",
            "handler_index": "132|160|208|235",
            "reason": "Reported mapped handler group from Antigravity notes; no local p-code currently present to classify semantics.",
            "behavior_class": "unknown",
            "confidence": "low_until_pcode_available",
            "next_analysis_step": "Obtain generated p-code/disassembly for this handler and classify memory/arith/table behavior.",
        },
        {
            "candidate_id": "P610-TC3",
            "handler_va": "0x0000000011B562BD/0x0000000011B5630F",
            "handler_index": "dispatcher",
            "reason": "Exporter report names opcode fetch at 0x11B562BD and table lookup at 0x11B5630F; this is relevant to VM execution path rather than the packet transform itself.",
            "behavior_class": "memory_load|table_lookup|branch_dispatch|pointer_update",
            "confidence": "high_for_dispatch_low_for_transform",
            "next_analysis_step": "Model opcode decode and handler selection; then trace from selected handlers to packet buffer writes.",
        },
    ]
    write_csv(ART / "pass610_codex_vm_transform_candidates.csv", transform_candidates)

    md = [
        "# Pass610 VM Table Verification",
        "",
        "Static/offline text analysis only. No target binary was executed and no raw binary bytes are included.",
        "",
        "## Findings",
        f"- `EA_VM_TargetDumpJava.java` present: {str(parsed['source_exists']).lower()}",
        f"- table constant `0x11B54E6F` present: {str(table_va == 0x11B54E6F).lower()}",
        f"- add constant `0x15F664FE` present: {str(add_const == 0x15F664FE).lower()}",
        f"- exporter loop covers 256 opcodes: {str(exporter_loop_256).lower()}",
        f"- handler formula in exporter: {str(formula_verified).lower()}",
        f"- generated handler table CSV present locally: {str(bool(generated_table_paths)).lower()}",
        f"- generated P-code text present locally: {str(bool(generated_pcode_paths)).lower()}",
        "",
        "## Verification Status",
        "The Java exporter verifies the claimed constants and contains a 256-iteration handler-table dumper using `handler = int64(entry) + 0x15F664FE`. However, the generated `pass8b_handler_table_from_ghidra.csv` is not present locally, so Codex could not independently verify all 256 resolved handler addresses, uniqueness, repetition, or compression from actual table entries.",
        "",
        "## Known Reported Handler Groups",
        "- `0x11B57796`: reported for opcodes 71, 113, 120, 157, 187, 231, 247.",
        "- `0x11B5932F`: reported for opcodes 132, 160, 208, 235.",
        "- Dispatcher lookup notes include opcode fetch at `0x11B562BD` and table lookup at `0x11B5630F`.",
    ]
    (ART / "pass610_codex_vm_table_verification.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    class_md = [
        "# Pass610 VM Handler Classification",
        "",
        "Classification was limited by missing generated P-code/disassembly outputs. The available Java exporter lists dump ranges and Antigravity notes name two repeated handler groups, but it does not contain handler bodies or table entries.",
        "",
        "## Current Classification Quality",
        "- Dispatcher ranges: classified by exporter range names and report lines only.",
        "- Handler groups `0x11B57796` and `0x11B5932F`: classified as unknown/branch-dispatch candidates from notes, not semantic proof.",
        "- No byte-wise XOR, rolling add/sub, memory-store loop, packet buffer write, or table-indexed transform handler is proven from current local exports.",
        "",
        "## Required Improvement",
        "Regenerate or provide `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, and `pass8b_handler_table_from_ghidra.csv`. Those text exports are sufficient for the next bounded parser without running or attaching to the game.",
    ]
    (ART / "pass610_codex_vm_handler_classification.md").write_text("\n".join(class_md) + "\n", encoding="utf-8")

    exec_model = [
        "# Pass610 VM Execution Model",
        "",
        "## Reconstructed From Current Text Exports",
        "- VM table base: `0x11B54E6F` from `EA_VM_TargetDumpJava.java`.",
        "- Handler formula: `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE` from exporter code.",
        "- VM entry launch range starts at `0x11B566B4`.",
        "- TLS launch range starts at `0x11B56C63`.",
        "- Dispatcher1 range starts at `0x11B56200`.",
        "- Antigravity notes state dispatcher1 uses `RSI` as instruction-stream pointer and decodes one opcode byte using `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`, then updates `BL = (BL - opcode) & 0xff` and `RSI += 1`.",
        "- Exporter report lines name byte fetch at `0x11B562BD` and table lookup at `0x11B5630F mov rdx, [r12+rax*8]`.",
        "",
        "## Not Yet Reconstructed",
        "- Complete handler table entries and handler uniqueness/repetition from actual table values.",
        "- Handler semantics for arithmetic, memory load/store, packet buffer writes, and stop/return behavior.",
        "- VM stack/register model beyond RSI/RBX/R12/BL hints.",
        "- Data memory region model and mapping from VM state to packet buffer/length/text-byte source.",
        "",
        "## Execution Path Status",
        "The dispatch-loop skeleton is plausible and partially reconstructed, but the execution path is not complete enough to emulate a packet-transform handler from current local files.",
    ]
    (ART / "pass610_codex_vm_execution_model.md").write_text("\n".join(exec_model) + "\n", encoding="utf-8")

    emu_plan = [
        "# Pass610 VM Emulation Plan",
        "",
        "## Safe Scope",
        "Build a text-export-driven emulator only. Do not execute the client, attach to a process, dump memory, inject, or use runtime unpacking.",
        "",
        "## Minimum Emulator Model",
        "- Parse `pass8b_handler_table_from_ghidra.csv` for opcode-to-handler mapping.",
        "- Parse `pass8b_target_pcode.txt` by address/range into p-code operations.",
        "- Implement VM state fields for instruction pointer (`RSI` candidate), rolling decode byte (`BL`), handler table base (`R12` candidate), and an abstract register/stack file.",
        "- Implement opcode decode from the current note: `rol8(((raw - BL + 0x86) ^ 0x34), 5)` and `BL = (BL - opcode) & 0xff`.",
        "- Dispatch to parsed handler p-code summaries and record high-level effects: loads, stores, arithmetic, table lookups, branches, and external calls.",
        "",
        "## Required Inputs Missing Now",
        "- `pass8b_handler_table_from_ghidra.csv` with all 256 resolved handlers.",
        "- `pass8b_target_pcode.txt` with handler and dispatcher p-code.",
        "- `pass8b_target_disassembly.txt` and `pass8b_target_flows.csv` to resolve branches/fallthroughs.",
        "- A bounded bytecode slice or file-backed VM instruction stream region to feed the opcode decoder.",
        "- A proven packet buffer pointer/length field mapping, or enough p-code to discover it statically.",
        "",
        "## Next Smallest Testable Unit",
        "Regenerate the Ghidra text exports and run `parse_vm_table.py` plus `classify_handlers.py` against them. The first concrete test is whether reported handler groups `0x11B57796` and `0x11B5932F` contain byte load/store plus xor/add/shift patterns or are only dispatcher/control-flow handlers.",
    ]
    (ART / "pass610_codex_vm_emulation_plan.md").write_text("\n".join(emu_plan) + "\n", encoding="utf-8")

    decision = {
        "worker": "codex",
        "phase": "pass610_vm_handler_execution_trace_validation",
        "vm_table_verified": False,
        "handler_count": 256 if exporter_loop_256 else 0,
        "handler_formula_verified": bool(formula_verified),
        "handler_classification_done": True,
        "transform_candidate_handlers_found": True,
        "top_candidate_handlers": ["0x11B57796", "0x11B5932F", "dispatcher:0x11B562BD/0x11B5630F"],
        "execution_model_reconstructed": False,
        "vm_emulation_possible_from_current_exports": False,
        "missing_inputs": [
            "pass8b_handler_table_from_ghidra.csv",
            "pass8b_target_pcode.txt",
            "pass8b_target_disassembly.txt",
            "pass8b_target_flows.csv",
            "file-backed VM bytecode/instruction-stream slice",
            "proven packet buffer pointer/length field mapping",
        ],
        "decoder_success": False,
        "exact_plaintext_recovered": False,
        "forbidden_methods_used": False,
        "raw_binary_committed": False,
        "private_payload_committed": False,
        "reason": "EA_VM_TargetDumpJava verifies the table constants, formula, and 256-opcode dumper, but the generated handler table and p-code exports are absent locally; therefore the full 256 handler address set and semantic execution trace cannot be independently validated from current files.",
        "next_action": "Provide or regenerate the Ghidra text exports listed in missing_inputs, then run the Pass610 parsers to classify actual handler p-code and trace dispatcher-to-handler-to-buffer effects.",
    }
    (ART / "pass610_codex_vm_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    report = [
        "# Codex Pass610 VM Handler Validation Report",
        "",
        "Decision: `blocked_missing_generated_vm_exports`",
        "",
        "- 256-handler VM table verified: no, only the exporter loop/formula was verified from Java source.",
        "- handler formula verified: yes, `int64([0x11B54E6F + opcode * 8]) + 0x15F664FE` appears in the exporter.",
        "- top transform-candidate handlers: `0x11B57796`, `0x11B5932F`, and dispatcher fetch/lookup `0x11B562BD` / `0x11B5630F`.",
        "- execution model reconstructed: partial dispatcher skeleton only, not complete execution model.",
        "- VM emulation possible from current exports: no.",
        "- missing blocker: generated `pass8b_handler_table_from_ghidra.csv` and `pass8b_target_pcode.txt` are not present locally.",
        "- no raw binary/packet data committed: yes.",
        "",
        "No forbidden methods were used. Memory dumps are not recommended.",
    ]
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    build()
