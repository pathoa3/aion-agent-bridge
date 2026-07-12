"""
trace_dispatcher_entry_registers.py
====================================
Statically traces how RDX (VM context pointer), RSI (bytecode base),
and RBX/BL (opcode key) are initialized before the VM dispatcher
(FUN_11b5625b at 0x11B5625B) is entered.

Uses local Ghidra pcode/disasm exports from pass622 only.
No runtime execution, no binary patching.

Two dispatcher entry paths are identified:

PATH A: FUN_11b5863d -> FUN_11b56b2c -> 0x11B5625B (direct)
  Called from: FUN_11b57bdb (via FUN_11b5863d -> FUN_11b56b2c)
  This path sets RSI = RBP (at 0x11B56B4B) before branching to dispatcher.

PATH B: FUN_11b45846 -> FUN_11b56999 -> thunk_FUN_11b59337
       -> FUN_11b59337 -> FUN_11b59832/11b59838 -> 0x11B5625B
  This path goes through the receive wrapper chain.

Ghidra SLEIGH register numbering (x86-64 AMD64):
  register 0x00 (8 bytes) = RAX / AL (1 byte)
  register 0x08 (8 bytes) = RCX / CL
  register 0x10 (8 bytes) = RDX / DL
  register 0x18 (8 bytes) = RBX / BL
  register 0x20 (8 bytes) = RSP / SPL
  register 0x28 (8 bytes) = RBP / BPL
  register 0x30 (8 bytes) = RSI / SIL
  register 0x38 (8 bytes) = RDI / DIL
  register 0x80 (8 bytes) = R8
  register 0x88 (8 bytes) = R9
  register 0x90 (8 bytes) = R10
  register 0x98 (8 bytes) = R11
  register 0xa0 (8 bytes) = R12
  register 0xa8 (8 bytes) = R13
  register 0xb0 (8 bytes) = R14
  register 0xb8 (8 bytes) = R15
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# Register name map (Ghidra SLEIGH offset -> name)
# ─────────────────────────────────────────────────────────────────────────────
REG = {
    0x00: "RAX", 0x08: "RCX", 0x10: "RDX", 0x18: "RBX",
    0x20: "RSP", 0x28: "RBP", 0x30: "RSI", 0x38: "RDI",
    0x80: "R8",  0x88: "R9",  0x90: "R10", 0x98: "R11",
    0xa0: "R12", 0xa8: "R13", 0xb0: "R14", 0xb8: "R15",
}

# ─────────────────────────────────────────────────────────────────────────────
# Complete register propagation trace from pcode analysis
# Each entry: (address, pcode_op, effect_description, confidence)
# ─────────────────────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════════════
# PATH A: FUN_11b5863d -> FUN_11b56b2c -> FUN_11b5625b  (dispatcher direct)
# ══════════════════════════════════════════════════════════════════════════════
PATH_A_TRACE = [
    # ── FUN_11b56b2c (called from FUN_11b5863d) ──────────────────────────────
    # Entry: RBP = context struct pointer (passed as parameter / set by caller)
    # RSI state at entry is unknown (from prior handler chain)
    {
        "address":    "0x11B56B43",
        "function":   "FUN_11b56b2c",
        "pcode":      "(register, 0xa8, 8) COPY (register, 0x0, 8)",
        "effect":     "R13 = RAX (junk from prior arithmetic)",
        "reg_target": "R13",
        "confidence": "low",
        "note":       "Junk assignment, does not affect key registers",
    },
    {
        "address":    "0x11B56B4B",
        "function":   "FUN_11b56b2c",
        "pcode":      "(register, 0x30, 8) COPY (register, 0x28, 8)",
        "effect":     "RSI = RBP  *** KEY: bytecode pointer base = VM context pointer ***",
        "reg_target": "RSI",
        "confidence": "high",
        "note":       "RSI is set to the VM context struct pointer (RBP). "
                      "Then dispatcher does RSI += LOAD[RBP] to advance to current PC.",
    },
    {
        "address":    "0x11B56B4E",
        "function":   "FUN_11b56b2c",
        "pcode":      "(register, 0x28, 4) INT_SEXT (register, 0x18, 1) → RBP = sign_ext(BL)",
        "effect":     "RBP = sign_extend(BL) — but BL here is obfuscated junk from prior ops",
        "reg_target": "RBP",
        "confidence": "low",
        "note":       "RBP is obfuscated after RSI copy. The actual VM context pointer "
                      "was already copied to RSI at 0x11B56B4B.",
    },
    {
        "address":    "0x11B56B8D",
        "function":   "FUN_11b56b2c",
        "pcode":      "(register, 0x28, 8) COPY (register, 0x20, 8)",
        "effect":     "RBP = RSP (frame pointer reset)",
        "reg_target": "RBP",
        "confidence": "medium",
        "note":       "RBP is overwritten with RSP before dispatch. "
                      "RSI already holds the true bytecode base.",
    },
    {
        "address":    "0x11B56B97",
        "function":   "FUN_11b56b2c",
        "pcode":      "(register, 0x20, 8) INT_SUB (register, 0x20, 8), (const, 0x140, 8)",
        "effect":     "RSP -= 0x140  (allocate stack frame for dispatcher)",
        "reg_target": "RSP",
        "confidence": "high",
        "note":       "Stack reservation before branching to FUN_11b5625b",
    },
    {
        "address":    "0x11B56BAF",
        "function":   "FUN_11b56b2c",
        "pcode":      "BRANCH (ram, 0x11b5625b, 8)",
        "effect":     "JMP to dispatcher FUN_11b5625b. "
                      "At this point: RSI = original RBP (context ptr). "
                      "RBP = RSP (stack ptr). BL/RBX = unknown (from caller chain).",
        "reg_target": "PC",
        "confidence": "high",
        "note":       "Dispatcher entry via PATH A. RSI = VM context pointer.",
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# PATH B: FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838 -> FUN_11b5625b
# ══════════════════════════════════════════════════════════════════════════════
PATH_B_TRACE = [
    # ── FUN_11b45846 (network receive entry) ──────────────────────────────────
    {
        "address":    "0x11B45846",
        "function":   "FUN_11b45846",
        "pcode":      "PUSH const 0xffffffff9462f3f0; CBRANCH; BRANCH 0x11B566DD",
        "effect":     "Push junk constant to stack; conditional branch to FUN_11b566dd loop",
        "reg_target": "N/A",
        "confidence": "high",
        "note":       "Entry point. RCX=this/socket, RDX=buffer, R8=length (Windows ABI). "
                      "Register sources for the VM (RDX/RSI/RBX) are NOT set here.",
    },
    # ── FUN_11b56999 (called by FUN_11b45846) ────────────────────────────────
    {
        "address":    "0x11B569A7",
        "function":   "FUN_11b56999",
        "pcode":      "(register, 0x28, 8) COPY (register, 0x38, 8)",
        "effect":     "RBP = RDI  (saves RDI as temporary context)",
        "reg_target": "RBP",
        "confidence": "high",
        "note":       "RBP temporarily = RDI (7th argument or scratch). "
                      "This is overwritten by FUN_11b59337.",
    },
    {
        "address":    "0x11B569B1",
        "function":   "FUN_11b56999",
        "pcode":      "(register, 0x28, 8) COPY (const, 0xa9b6d973, 8)",
        "effect":     "RBP = 0xa9b6d973  (obfuscation constant, overwrites prior RBP)",
        "reg_target": "RBP",
        "confidence": "high",
        "note":       "Junk assignment — all prior RBP value is destroyed. "
                      "FUN_11b59337 will overwrite again.",
    },
    {
        "address":    "0x11B569B6",
        "function":   "FUN_11b56999",
        "pcode":      "BRANCH (ram, 0x11b56075, 8)",
        "effect":     "JMP to thunk_FUN_11b59337 -> FUN_11b59337",
        "reg_target": "PC",
        "confidence": "high",
        "note":       "FUN_11b56999 jumps to FUN_11b59337 via thunk at 0x11B56075.",
    },
    # ── FUN_11b59337 (receive wrapper, sets RBP = RDX) ───────────────────────
    {
        "address":    "0x11B59337",
        "function":   "FUN_11b59337",
        "pcode":      "(register, 0x20, 8) INT_SUB (register, 0x20, 8), (const, 0x8, 8); "
                      "STORE RSP, RBX",
        "effect":     "PUSH RBX (saves caller's RBX to stack)",
        "reg_target": "RBX",
        "confidence": "high",
        "note":       "RBX is preserved. Whatever RBX held from the caller is now on stack. "
                      "This is where BL (VM key byte) comes from if it survives.",
    },
    {
        "address":    "0x11B59343",
        "function":   "FUN_11b59337",
        "pcode":      "(register, 0x28, 8) COPY (register, 0x10, 8)",
        "effect":     "RBP = RDX  *** KEY: VM context pointer = 2nd call argument ***",
        "reg_target": "RBP",
        "confidence": "high",
        "note":       "RBP is definitively set to RDX here. RDX is the 2nd argument "
                      "(Windows x64 ABI: RCX=arg1, RDX=arg2). "
                      "The VM context struct is passed as the 2nd argument to FUN_11b59337.",
    },
    {
        "address":    "0x11B5934B",
        "function":   "FUN_11b59337",
        "pcode":      "BSWAP(register 0x28 / RBP dword) -> INT_ZEXT",
        "effect":     "RBP = BSWAP32(RBP_low32) (byte-swap obfuscation)",
        "reg_target": "RBP",
        "confidence": "medium",
        "note":       "RBP is byte-swapped. This is obfuscation; actual context pointer "
                      "is in the original RDX value. The dispatcher corrects for this "
                      "via the ADD RSI, LOAD[RBP] at 0x11B562AE which loads from the "
                      "BSWAPPED address — unless RBP is restored before use.",
    },
    {
        "address":    "0x11B5934E",
        "function":   "FUN_11b59337",
        "pcode":      "BRANCH (ram, 0x11b59832, 8)",
        "effect":     "JMP to FUN_11b59832 (dispatcher entry wrapper = FUN_11b59838)",
        "reg_target": "PC",
        "confidence": "high",
        "note":       "Jumps to 0x11B59832 which is the entry to FUN_11b59838.",
    },
    # ── FUN_11b59838 (dispatcher wrapper) ────────────────────────────────────
    {
        "address":    "0x11B59839",
        "function":   "FUN_11b59838",
        "pcode":      "(register, 0x20, 8) INT_SUB (register, 0x20, 8), (const, 0x140, 8)",
        "effect":     "RSP -= 0x140  (allocate stack frame for dispatcher)",
        "reg_target": "RSP",
        "confidence": "high",
        "note":       "Standard stack allocation before dispatcher entry.",
    },
    {
        "address":    "0x11B5984A",
        "function":   "FUN_11b59838",
        "pcode":      "BRANCH (ram, 0x11b5625b, 8)",
        "effect":     "JMP to dispatcher FUN_11b5625b. "
                      "At this point: RBP = BSWAP32(RDX_from_caller). "
                      "RSI = unknown (from caller). BL = caller's RBX (push-preserved).",
        "reg_target": "PC",
        "confidence": "high",
        "note":       "Dispatcher entry via PATH B.",
    },
    # ── FUN_11b5625b (dispatcher) - RSI initialization ───────────────────────
    {
        "address":    "0x11B562AE",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0x30, 8) INT_ADD (register, 0x30, 8), LOAD[RBP]",
        "effect":     "RSI += *RBP  (advance bytecode pointer by PC offset in context struct)",
        "reg_target": "RSI",
        "confidence": "high",
        "note":       "RSI is the bytecode instruction pointer. "
                      "It starts as the bytecode BASE (set in PATH A by RSI=RBP). "
                      "In PATH B, RSI comes from the caller chain. "
                      "The LOAD[RBP] reads the PC offset from [RBP+0], "
                      "adding it to the base RSI to get the current instruction pointer.",
    },
    {
        "address":    "0x11B562BD",
        "function":   "FUN_11b5625b",
        "pcode":      "(unique, 0x23b00, 1) LOAD (const, 0x1b1, 4), (register, 0x30, 8); "
                      "(register, 0x0, 1) COPY (unique, 0x23b00, 1)",
        "effect":     "AL = LOAD[RSI]  (fetch raw opcode byte from bytecode stream)",
        "reg_target": "AL",
        "confidence": "high",
        "note":       "This is the bytecode fetch. RSI must point to valid .aion1 bytecode.",
    },
    {
        "address":    "0x11B562CC",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0x0, 1) INT_SUB (register, 0x0, 1), (register, 0x18, 1)",
        "effect":     "AL = AL - BL  (opcode decryption step 1: subtract rolling key)",
        "reg_target": "AL",
        "confidence": "high",
        "note":       "BL (register 0x18, size 1) is the rolling decryption key. "
                      "This confirms BL must be initialized BEFORE dispatcher entry.",
    },
    {
        "address":    "0x11B562D5",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0x0, 1) INT_ADD (register, 0x0, 1), (const, 0x86, 1)",
        "effect":     "AL = AL + 0x86  (opcode decryption step 2)",
        "reg_target": "AL",
        "confidence": "high",
        "note":       "Part of opcode decode: AL = (AL - BL + 0x86) & 0xFF",
    },
    {
        "address":    "0x11B562D9",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0x0, 1) INT_XOR (register, 0x0, 1), (const, 0x34, 1)",
        "effect":     "AL = AL ^ 0x34  (opcode decryption step 3)",
        "reg_target": "AL",
        "confidence": "high",
        "note":       "Part of opcode decode: AL = ((AL - BL + 0x86) ^ 0x34) & 0xFF",
    },
    {
        "address":    "0x11B562E3",
        "function":   "FUN_11b5625b",
        "pcode":      "INT_LEFT/INT_RIGHT of AL by const 0x5",
        "effect":     "AL = rol8(AL, 5)  (opcode decryption step 4: 8-bit left rotate by 5)",
        "reg_target": "AL",
        "confidence": "high",
        "note":       "Full decode: opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5). Confirmed.",
    },
    {
        "address":    "0x11B56278",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0xa0, 8) COPY (const, 0x11b54e6f, 8)",
        "effect":     "R12 = 0x11B54E6F  (handler table base, hardcoded constant)",
        "reg_target": "R12",
        "confidence": "high",
        "note":       "Handler table base is a static constant — no runtime dependency.",
    },
    {
        "address":    "0x11B5630F",
        "function":   "FUN_11b5625b",
        "pcode":      "(register, 0x10, 8) COPY LOAD[R12 + RAX*8]",
        "effect":     "RAX = handler_table[opcode]  (handler VA lookup)",
        "reg_target": "RAX",
        "confidence": "high",
        "note":       "Dispatches to one of 256 handlers via R12-relative table.",
    },
    {
        "address":    "0x11B56329",
        "function":   "FUN_11b5625b",
        "pcode":      "BRANCHIND (register, 0x10, 8)",
        "effect":     "JMP RAX  (dispatch to VM handler)",
        "reg_target": "PC",
        "confidence": "high",
        "note":       "Final dispatch.",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Register source summary
# ─────────────────────────────────────────────────────────────────────────────
REGISTER_SOURCES = [
    {
        "reg":           "RDX => RBP",
        "source_function": "FUN_11b59337",
        "source_address":  "0x11B59343",
        "source_kind":     "parameter",
        "value_or_origin": "RDX = 2nd call argument to FUN_11b59337 (Windows x64 ABI)",
        "evidence":        "pcode: (register, 0x28, 8) COPY (register, 0x10, 8)",
        "confidence":      "high",
        "next_test":       "Find who calls FUN_11b59337 / FUN_11b56999 and what is in RDX at callsite",
    },
    {
        "reg":           "RSI (bytecode base, PATH A)",
        "source_function": "FUN_11b56b2c",
        "source_address":  "0x11B56B4B",
        "source_kind":     "register_copy",
        "value_or_origin": "RSI = RBP (VM context pointer at entry to FUN_11b56b2c)",
        "evidence":        "pcode: (register, 0x30, 8) COPY (register, 0x28, 8)",
        "confidence":      "high",
        "next_test":       "Find what RBP is on entry to FUN_11b56b2c from FUN_11b5863d",
    },
    {
        "reg":           "RSI (bytecode ptr init, dispatcher)",
        "source_function": "FUN_11b5625b",
        "source_address":  "0x11B562AE",
        "source_kind":     "computed",
        "value_or_origin": "RSI = RSI_base + LOAD[RBP]  (RSI_base += PC_offset from context)",
        "evidence":        "pcode: (register, 0x30, 8) INT_ADD ..., LOAD (register, 0x28, 8)",
        "confidence":      "high",
        "next_test":       "Determine RSI_base value and [RBP+0] PC offset at dispatch time",
    },
    {
        "reg":           "RBX/BL (VM key byte)",
        "source_function": "FUN_11b59337",
        "source_address":  "0x11B59337",
        "source_kind":     "caller_preserved",
        "value_or_origin": "RBX saved (PUSH) on entry; BL comes from caller of FUN_11b59337",
        "evidence":        "pcode: STORE RSP, RBX (push RBX at function entry)",
        "confidence":      "medium",
        "next_test":       "Trace what RBX/BL is in FUN_11b45846/FUN_11b56999 before the call",
    },
    {
        "reg":           "R12 (handler table base)",
        "source_function": "FUN_11b5625b",
        "source_address":  "0x11B56278",
        "source_kind":     "constant",
        "value_or_origin": "0x11B54E6F (hardcoded)",
        "evidence":        "pcode: (register, 0xa0, 8) COPY (const, 0x11b54e6f, 8)",
        "confidence":      "high",
        "next_test":       "None - fully resolved",
    },
    {
        "reg":           "[RBP+0x00] (PC offset / VM instruction counter)",
        "source_function": "FUN_11b5625b",
        "source_address":  "0x11B562AE",
        "source_kind":     "memory_load",
        "value_or_origin": "LOAD[RBP]: loaded from VM context struct at offset +0",
        "evidence":        "pcode: LOAD (const, 0x1b1, 4), (register, 0x28, 8)",
        "confidence":      "high",
        "next_test":       "Find the context struct layout: what is at offset 0 of the context "
                           "pointer passed as RDX to FUN_11b59337?",
    },
    {
        "reg":           "RBP (PATH A, at dispatcher entry)",
        "source_function": "FUN_11b56b2c",
        "source_address":  "0x11B56B8D",
        "source_kind":     "register_copy",
        "value_or_origin": "RBP = RSP (stack pointer, frame setup)",
        "evidence":        "pcode: (register, 0x28, 8) COPY (register, 0x20, 8)",
        "confidence":      "high",
        "next_test":       "RSI (= original RBP/context ptr) is the key; RBP here is stack",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher entry candidates
# ─────────────────────────────────────────────────────────────────────────────
ENTRY_CANDIDATES = [
    {
        "candidate_id":      "EC-001",
        "path":              "A",
        "entry_function":    "FUN_11b5863d -> FUN_11b56b2c -> 0x11B5625B",
        "rdx_context_source": "RBP at entry to FUN_11b56b2c = caller-provided context",
        "rbp_pc_offset":      "LOAD[RBP] in dispatcher: value from context struct offset 0",
        "rsi_base":           "RSI = RBP (set at 0x11B56B4B) = VM context pointer",
        "rbx_bl_source":      "BL from prior handler chain (not directly traceable)",
        "static_resolved":    False,
        "confidence":         "medium",
        "next_test":          "Inspect FUN_11b5863d pcode for what RBP holds at entry",
    },
    {
        "candidate_id":      "EC-002",
        "path":              "B",
        "entry_function":    "FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838 -> 0x11B5625B",
        "rdx_context_source": "RDX = 2nd arg to FUN_11b59337 = 2nd arg of FUN_11b45846 (network recv buffer context)",
        "rbp_pc_offset":      "LOAD[BSWAP32(RDX)] from context struct at offset 0",
        "rsi_base":           "RSI = unknown (from caller chain of FUN_11b45846)",
        "rbx_bl_source":      "RBX preserved from FUN_11b45846 caller (PUSH at FUN_11b59337 entry)",
        "static_resolved":    False,
        "confidence":         "medium",
        "next_test":          "Find what FUN_11b45846 receives as RDX (network receive buffer struct?)",
    },
    {
        "candidate_id":      "EC-003",
        "path":              "A",
        "entry_function":    "FUN_11b5591a -> 0x11B5625B",
        "rdx_context_source": "N/A - different path",
        "rbp_pc_offset":      "N/A",
        "rsi_base":           "RSI = set in FUN_11b5591a (see call_edges: 0x11B5591A -> FUN_11b5625b)",
        "rbx_bl_source":      "Unknown",
        "static_resolved":    False,
        "confidence":         "low",
        "next_test":          "Export FUN_11b5591a pcode to inspect RSI/RBX setup",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Print and write results
# ─────────────────────────────────────────────────────────────────────────────
def print_path(name: str, trace: list[dict]):
    print(f"\n{'='*80}")
    print(f"  {name}")
    print(f"{'='*80}")
    for step in trace:
        addr = step["address"]
        fn   = step["function"]
        eff  = step["effect"]
        conf = step["confidence"]
        note = step.get("note", "")
        print(f"  [{addr}] {fn}")
        print(f"    Effect: {eff}")
        if note:
            print(f"    Note  : {note}")
        print(f"    Conf  : {conf}")
        print()


def write_register_sources_csv(rows: list[dict], path: str):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["reg","source_function","source_address","source_kind",
                      "value_or_origin","evidence","confidence","next_test"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nRegister sources written to: {path}")


def write_entry_candidates_csv(rows: list[dict], path: str):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["candidate_id","rdx_context_source","rbp_pc_offset",
                      "rsi_base","rbx_bl_source","static_resolved",
                      "confidence","next_test"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Entry candidates written to: {path}")


def main():
    print("VM Dispatcher Entry Register Trace")
    print("=" * 80)
    print()
    print("Ghidra SLEIGH register map (key registers):")
    for off, name in sorted(REG.items()):
        if off in [0x10, 0x18, 0x28, 0x30, 0xa0]:
            print(f"  reg 0x{off:02X} = {name}")
    print()

    print_path("PATH A: FUN_11b5863d -> FUN_11b56b2c -> FUN_11b5625b", PATH_A_TRACE)
    print_path("PATH B: FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838 -> FUN_11b5625b",
               PATH_B_TRACE)

    print("\n" + "=" * 80)
    print("  REGISTER SOURCE SUMMARY")
    print("=" * 80)
    for r in REGISTER_SOURCES:
        print(f"\n  Register   : {r['reg']}")
        print(f"  Function   : {r['source_function']} @ {r['source_address']}")
        print(f"  Kind       : {r['source_kind']}")
        print(f"  Value      : {r['value_or_origin']}")
        print(f"  Evidence   : {r['evidence']}")
        print(f"  Confidence : {r['confidence']}")
        print(f"  Next test  : {r['next_test']}")

    print("\n" + "=" * 80)
    print("  WHAT IS STATICALLY RESOLVED vs BLOCKED")
    print("=" * 80)
    resolved = [
        ("R12 (handler table base)", "0x11B54E6F — hardcoded constant in dispatcher pcode"),
        ("Opcode decode formula",    "opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5) — confirmed"),
        ("BL update formula",        "BL = (BL - opcode) & 0xFF — confirmed"),
        ("Bytecode fetch address",   "RSI = VM context pointer (PATH A: set at 0x11B56B4B)"),
        ("Dispatcher branch site",   "0x11B56329: BRANCHIND RAX — confirmed"),
    ]
    blocked = [
        ("RDX (VM context pointer)", "Runtime argument to FUN_11b59337 — need callsite with RDX value"),
        ("[RBP+0] PC offset",        "Runtime field in VM context struct — struct layout unknown"),
        ("RSI base (PATH B)",        "Not set by any statically traced function in PATH B chain"),
        ("RBX/BL initial value",     "Preserved from caller; caller chain of FUN_11b45846 not exported"),
        ("Context struct layout",    "No static struct definition found in Ghidra exports"),
    ]
    print("\n  RESOLVED:")
    for name, desc in resolved:
        print(f"    [OK] {name}: {desc}")
    print("\n  BLOCKED:")
    for name, desc in blocked:
        print(f"    [--] {name}: {desc}")

    import os; os.makedirs("artifacts", exist_ok=True)
    write_register_sources_csv(REGISTER_SOURCES, "artifacts/pass628_antigravity_register_sources.csv")
    write_entry_candidates_csv(ENTRY_CANDIDATES, "artifacts/pass628_antigravity_dispatcher_entry_candidates.csv")


if __name__ == "__main__":
    main()
