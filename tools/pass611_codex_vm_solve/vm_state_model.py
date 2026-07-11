"""Emit the current VM state model from available static artifacts."""
from __future__ import annotations

import csv
from parse_existing_vm_exports import ARTIFACTS, load_context

LAYOUT_ROWS = [
    ("RSI", "VM instruction pointer / encrypted bytecode stream pointer", "Pass610 execution model says VIP fetches raw byte from [RSI] then increments RSI", "high", "Bytecode stream, not proven packet buffer"),
    ("BL", "rolling VM opcode decode key", "Opcode decode formula uses BL; BL updates as (BL - opcode) & 0xff", "high", "Lower byte of RBX"),
    ("RBX", "VM state/key carrier at dispatcher entry", "Prior model maps BL to RBX low byte and says RBX is set from RSI at dispatcher entry", "medium", "Exact full struct role needs p-code"),
    ("RBP", "VM scratch stack/frame base", "Pass610 execution model identifies scratch temporaries via [RBP + delta]", "medium", "Offsets not fully exported"),
    ("0x11B54E6F", "VM handler dispatch table base", "EA_VM_TargetDumpJava constants and Pass610 table progress", "high", "256 opcode entries"),
    ("0x15F664FE", "handler-address add constant", "handler_va = int64([table + opcode*8]) + constant", "high", "Formula only, not transform"),
    ("[RSI + 0x18]", "bytecode base pointer", "Antigravity P609 edge notes", "medium", "Not independently confirmed by p-code in Codex"),
    ("[RSI + 0x24]", "candidate packet buffer pointer", "Antigravity P609 edge notes", "low-medium", "Rejected edge does not prove writes to this field"),
    ("[RBX + 0x48]", "candidate rolling crypto/session state", "Antigravity P609 edge notes", "low-medium", "Needs full handler p-code"),
    ("[RBX + 0x50]", "candidate packet length variable", "Antigravity P609 edge notes", "low-medium", "Needs write-side dataflow"),
]


def write_model(ctx: dict) -> int:
    with (ARTIFACTS / "pass611_codex_vm_context_layout.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["offset_or_register", "meaning", "evidence", "confidence", "notes"])
        writer.writerows(LAYOUT_ROWS)
    md = """# Pass611 Codex VM State Model\n\nCodex reconstructed the state model from existing text/CSV exports only. No target binary was run or attached.\n\n## Dispatch\n\n- Raw VM opcode byte is fetched from `[RSI]`.\n- Opcode decode formula from Pass610: `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`.\n- Rolling decode key update: `BL = (BL - opcode) & 0xff`.\n- Handler lookup: `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE`.\n- Pass610 artifacts report 70 unique handlers across 256 opcodes.\n\n## Current Packet-Buffer Model\n\nThe most specific packet-related fields remain candidates, not proven Codex facts. Available notes identify `[RSI + 0x24]` as a candidate packet buffer pointer, `[RBX + 0x50]` as a candidate length variable, and `[RBX + 0x48]` as candidate rolling crypto/session state. The P609-012 edge does not prove writes to these fields.\n\n## Missing for Decoder Derivation\n\nA handler-derived decoder needs full p-code/disassembly/dataflow for the top transform handlers, including register/memory inputs and writes. First-instruction classifications are enough to prioritize handlers, but not enough to derive a valid packet transform without guessing.\n"""
    (ARTIFACTS / "pass611_codex_vm_state_model.md").write_text(md, encoding="utf-8")
    return len(LAYOUT_ROWS)


if __name__ == "__main__":
    write_model(load_context())
