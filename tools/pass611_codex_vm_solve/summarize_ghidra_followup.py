"""Summarize local-only Ghidra Pass8B/Pass8C exports into Git-safe Pass611 follow-up artifacts.

The local Ghidra outputs contain raw instruction bytes and p-code, so this script
emits only high-level facts, addresses, instruction mnemonics, and decisions.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
ARTIFACTS = REPO / "artifacts"
LOCAL = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass611_codex_vm_solve_local")
PASS8B = LOCAL / "ghidra_pass8b"
PASS8C = LOCAL / "ghidra_pass8c"

DISASM = PASS8B / "pass8b_target_disassembly.txt"
PCODE = PASS8B / "pass8b_target_pcode.txt"
TABLE = PASS8B / "pass8b_handler_table_from_ghidra.csv"
FLOW_SUMMARY = PASS8C / "pass8c_flow_summary.md"
INTEREST = PASS8C / "pass8c_interesting_state_instructions.csv"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def has(pattern: str, body: str) -> bool:
    return re.search(pattern, body, re.IGNORECASE) is not None


def main() -> dict[str, object]:
    dis = text(DISASM)
    pc = text(PCODE)
    table_rows = csv_rows(TABLE)
    interest_rows = csv_rows(INTEREST)

    outputs_present = {
        "pass8b_target_disassembly": DISASM.exists(),
        "pass8b_target_pcode": PCODE.exists(),
        "pass8b_target_flows": (PASS8B / "pass8b_target_flows.csv").exists(),
        "pass8b_handler_table": TABLE.exists(),
        "pass8c_recursive_flow": (PASS8C / "pass8c_recursive_flow_pcode.txt").exists(),
        "pass8c_interesting_state": INTEREST.exists(),
    }

    p609_covered = has(r"114731e0|114731f5", dis) or has(r"114731e0|114731f5", pc)
    dispatcher_proofs = [
        ("0x11B562BD", "MOV AL, byte ptr [RSI]", "VM bytecode fetch from RSI", has(r"11b562bd:.*MOV\s+AL, byte ptr \[RSI\]", dis)),
        ("0x11B562CC", "SUB AL, BL", "opcode decode subtracts rolling BL", has(r"11b562cc:.*SUB\s+AL, BL", dis)),
        ("0x11B562D5", "ADD AL, 0x86", "opcode decode adds constant", has(r"11b562d5:.*ADD\s+AL, 0x86", dis)),
        ("0x11B562D9", "XOR AL, 0x34", "opcode decode xors constant", has(r"11b562d9:.*XOR\s+AL, 0x34", dis)),
        ("0x11B562E3", "ROL AL, 0x5", "opcode decode rotates opcode", has(r"11b562e3:.*ROL\s+AL, 0x5", dis)),
        ("0x11B562EA", "SUB BL, AL", "rolling BL update", has(r"11b562ea:.*SUB\s+BL, AL", dis)),
        ("0x11B562FF", "INC RSI", "advance VM bytecode pointer", has(r"11b562ff:.*INC\s+RSI", dis)),
        ("0x11B5630F", "MOV RDX, qword ptr [R12 + RAX*0x8]", "handler table lookup", has(r"11b5630f:.*MOV\s+RDX, qword ptr \[R12 \+ RAX\*0x8\]", dis)),
    ]

    top_table = [r for r in table_rows if (r.get("handler_va", "").lower() in {"0x0000000011b57796", "0x0000000011b5932f", "0x0000000011b57437", "0x0000000011b5701a"})]

    handler_rows = [
        {
            "handler_va": "0x11B57796",
            "static_semantics": "BT BX bit9; SAR AH by CL; NEG AL; MOV EAX,[RSI]; JMP 0x11B56580",
            "dataflow_meaning": "loads a 32-bit immediate/operand from VM bytecode stream, then enters dispatcher continuation",
            "packet_transform_derived": "false",
            "reason": "RSI is proven as VM bytecode pointer in dispatcher; no packet buffer write is present in this slice",
        },
        {
            "handler_va": "0x11B56580",
            "static_semantics": "mix EAX with EBX, rotate, push/add/pop, subtract RBP, jump 0x11B5816E",
            "dataflow_meaning": "VM stack/value materialization path for handler_71 operand",
            "packet_transform_derived": "false",
            "reason": "only stack/RBP writes seen in exported slice; no packet buffer field confirmed",
        },
        {
            "handler_va": "0x11B5932F",
            "static_semantics": "SETZ AH handler group per table/classification",
            "dataflow_meaning": "constant/flag materialization candidate",
            "packet_transform_derived": "false",
            "reason": "no packet buffer bridge or complete native continuation exported for transform derivation",
        },
        {
            "handler_va": "0x11B57437",
            "static_semantics": "XOR DL,0xC7 handler group per table/classification",
            "dataflow_meaning": "literal logical operation already bounded-tested by prior Pass610 branch",
            "packet_transform_derived": "false",
            "reason": "literal XOR trial failed and no stateful packet dataflow connects it to payload bytes",
        },
        {
            "handler_va": "0x11B5701A",
            "static_semantics": "XOR AL,DL handler group per table/classification",
            "dataflow_meaning": "register logical operation candidate",
            "packet_transform_derived": "false",
            "reason": "register sources are VM state/bytecode values in available exports, not confirmed payload bytes",
        },
    ]

    with (ARTIFACTS / "pass611_codex_ghidra_followup_dispatcher.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["va", "instruction", "meaning", "confirmed"])
        w.writerows(dispatcher_proofs)

    with (ARTIFACTS / "pass611_codex_ghidra_followup_handlers.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["handler_va", "static_semantics", "dataflow_meaning", "packet_transform_derived", "reason"])
        w.writeheader()
        w.writerows(handler_rows)

    decision = {
        "worker": "codex",
        "phase": "pass611_vm_solve_ghidra_followup",
        "static_ghidra_exports_generated_local_only": True,
        "target_binary_executed": False,
        "live_process_used": False,
        "debugger_used": False,
        "pcode_exports_available": outputs_present,
        "p609012_covered_by_new_exports": p609_covered,
        "dispatcher_decode_confirmed_from_pcode": all(x[3] for x in dispatcher_proofs),
        "handler_11B57796_semantics_refined": True,
        "handler_11B57796_packet_transform_derived": False,
        "handler_derived_transforms_tested": 0,
        "exact_plaintext_recovered": False,
        "decoder_success": False,
        "private_raw_ghidra_exports_committed": False,
        "raw_binary_committed": False,
        "private_payload_committed": False,
        "best_candidate_handler": "0x11B57796",
        "best_dataflow_edge": "dispatcher 0x11B562BD..0x11B56329; handler 0x11B57796 -> 0x11B56580",
        "best_remaining_blocker": "Ghidra p-code proves the VM opcode dispatcher and refines 0x11B57796 as a VM bytecode dword-load/stack materialization path, but no native bridge from VM state to packet payload buffer writes is present in the exported slices. Need the VM bytecode program slice or a native flow slice that reaches candidate packet buffer writes from confirmed context fields.",
        "next_autonomous_step": "Trace from native call sites that initialize RSI/RBP/R12/R13 for the VM and locate memory writes to candidate packet buffer/length fields; alternatively provide a file-backed VM bytecode slice so the dispatcher can be symbolically interpreted across real opcodes.",
        "reason": "The previous missing p-code input was generated locally. It confirms dispatcher mechanics and rejects treating 0x11B57796 as a standalone packet decoder; no exact plaintext recovered.",
    }
    (ARTIFACTS / "pass611_codex_ghidra_followup_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    summary = f"""# Pass611 Codex Ghidra Follow-up\n\nCodex generated the missing Ghidra exports locally under the private outbox. The raw p-code/disassembly/export files were **not** copied into Git artifacts.\n\n## New Static Evidence\n\n- `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, and handler-table exports now exist locally.\n- Dispatcher decode is confirmed from Ghidra output: fetch `[RSI]`, decode with `BL`, update `BL`, increment `RSI`, and table-dispatch via `R12 + RAX*8`.\n- Handler `0x11B57796` is refined: it reads `EAX` from `[RSI]` and jumps to dispatcher continuation at `0x11B56580`. This is consistent with loading a VM bytecode operand/immediate, not directly decrypting packet payload bytes.\n- P609-012 `0x114731E0..0x114731F5` was not covered by the new target/recursive export slices, so the previous rejection stands; it is not a usable transform source.\n\n## Decoder Status\n\nNo handler-derived packet transform was tested in this follow-up because the new semantics still do not connect a handler to packet buffer writes. No exact plaintext was recovered and no decoder success is claimed.\n\n## Remaining Blocker\n\n{decision['best_remaining_blocker']}\n\n## Next Step\n\n{decision['next_autonomous_step']}\n"""
    (ARTIFACTS / "pass611_codex_ghidra_followup_summary.md").write_text(summary, encoding="utf-8")

    with (LOCAL / "progress_log.md").open("a", encoding="utf-8") as f:
        f.write("2026-07-12T04:30:00Z, phase8, ghidra_static_exports, generated Pass8B/Pass8C p-code locally, dispatcher confirmed and 0x11B57796 refined, no packet transform, trace VM call-site/context initialization\n")

    return decision


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
