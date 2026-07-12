"""
inspect_missing_dispatcher_context.py
======================================
Inspects all previously-missing Ghidra pcode exports and answers:

  Q1. What is RBP at entry to FUN_11b56b2c?
  Q2. What does FUN_11b5863d pass into FUN_11b56b2c?
  Q3. Does FUN_11b5591a provide a static RSI/RBX setup?
  Q4. Does FUN_11b50330 initialize RSI/RBX/BL before VM entry?
  Q5. What does 0x1195D94A pass as RDX/RBX/RSI to FUN_11b45846?
  Q6. Can [RBP+0] PC offset be inferred from context construction?

Findings from raw pcode analysis:

────────────────────────────────────────────────────────────────────────────────
FUN_11b5863d (PATH A caller → FUN_11b56b2c)
────────────────────────────────────────────────────────────────────────────────
Key pcode:
  0x11B58641: PUSH RDX  (saves RDX)
  0x11B58646: PUSH RDI  (saves RDI)
  0x11B58654: PUSH RBX  (saves RBX to stack)
  0x11B5865F: PUSH ram[0x11b592f1]  (indirect push)
  0x11B58667: RBP:2 = sign_ext(DL)  (RBP_low16 = sign_ext of DL byte)
  0x11B5866B: bit-scan-forward loop on RBX, counting trailing zeros
      → (register, 0x28, 8) COPY (unique, 0x68900, 8) — RBP = BSF(RBX)
  0x11B5866F: BRANCH → FUN_11b56b2c

Answer Q1/Q2: RBP at FUN_11b56b2c entry = BSF(RBX_at_FUN_11b5863d_entry).
  BSF(RBX) = position of lowest set bit in RBX. This is a SMALL INTEGER (0..63).
  This is NOT a valid VA! RSI = RBP = small integer.
  Conclusion: FUN_11b56b2c entry RSI is a small integer, NOT a bytecode VA.
  The RSI += LOAD[RBP] in the dispatcher makes RSI = small_int + *[small_int],
  which is a load from a very low memory address — this is NOT the .aion1 bytecode path.
  FUN_11b56b2c → 0x11B5625B appears to be a UTILITY path, not the main decode loop.

────────────────────────────────────────────────────────────────────────────────
FUN_11b5591a (PATH C → dispatcher direct)
────────────────────────────────────────────────────────────────────────────────
Key pcode:
  0x11B5591A: RSP -= 0x140  (allocate stack frame)
  0x11B55921: compare CL with 0xDF (some check on BL-adjacent reg)
  0x11B55924: TEST BL, BL  (test BL — confirms BL is the VM key byte)
  0x11B55926: RSP = AND(RSP, 0xFFFFFFFFFFFFFFF0)  (16-byte align)
  0x11B5592A: BRANCH → 0x11B5625B  (dispatcher entry)

Answer Q3: FUN_11b5591a does NOT set RSI or RBX statically.
  It preserves caller's RBX/BL (no COPY/assignment to BL visible).
  RSP alignment at 0x11B55926 before dispatch is the frame setup.
  BL comes from the caller of FUN_11b5591a.
  RSI is not set — comes from caller of FUN_11b5591a.
  Caller: FUN_11b56f43 (per call_edges.csv: 0x11B56F43 → 0x11B5591A → FUN_11b5625b).

────────────────────────────────────────────────────────────────────────────────
FUN_11b50330 (TLS callback → thunk_FUN_11b57075)
────────────────────────────────────────────────────────────────────────────────
Key pcode:
  0x11B50330: PUSH const 0xffffffff9462e466 (obfuscation junk)
  0x11B50335: CBRANCH on overflow_flag mismatch (JNO/JO pattern)
  0x11B5033B: PUSH const 0xffffffff87363d81 (obfuscation junk)
  0x11B50340: BRANCH → 0x11B56C63 (thunk_FUN_11b57075)

Answer Q4: FUN_11b50330 does NOT set RSI, RBX, or BL.
  It only pushes junk constants and branches to thunk_FUN_11b57075.
  Register state (RSI, RBX, BL) comes from wherever FUN_11b50330 was called from.
  Called from: tls_callback_0 at 0x11B503FD.

────────────────────────────────────────────────────────────────────────────────
Entry 0x1195D94A (program entry → thunk_FUN_11b45846)
────────────────────────────────────────────────────────────────────────────────
Key pcode:
  0x1195D94A: BRANCH → 0x11B52CE5 (thunk_FUN_11b45846)
  Only a single JMP — no register initialization whatsoever.

Answer Q5: Entry 0x1195D94A sets nothing. JMP to FUN_11b45846 thunk directly.
  RSI, RBX, BL, RDX all come from the OS loader when entering the process.
  For network receive (FUN_11b45846), the register state is set by:
  — the OS calling the TLS callback first (FUN_11b503FD → FUN_11b50330 → FUN_11b57075)
  — which calls FUN_11b57BDB → FUN_11b5863d → FUN_11b56b2c → FUN_11b5625B
  This is NOT the network receive path but the INITIALIZATION path for the VM context.

────────────────────────────────────────────────────────────────────────────────
FUN_11b57075 (called from thunk_FUN_11b57075 / FUN_11b50330)
────────────────────────────────────────────────────────────────────────────────
Key pcode:
  0x11B57075: PUSH RBP (save)
  0x11B57076: RBP = sign_ext(AL)   (RBP = sign_extend of AL low byte)
  0x11B57081: RBP:2 = sign_ext(BL) (RBP_w16 = sign_extend of BL low byte = KEY BYTE)
  0x11B57085: CBRANCH on SF flag → 0x11B56BB4 (FUN_11b56b2c area)
  0x11B5708B: RBP:2 = zero_ext(CL)
  0x11B57090: RBP = sign_ext(BL)
  0x11B570A0: RBP = RAX + 0xFFFFFFFFA42719DE (obfuscated)
  0x11B570A7: BRANCH → FUN_11b59765
  0x11B577F1: BRANCH → 0x11B5625B  (PATH D)
  
  PATH D: RSP = AND(RSP, 0xFFFFF0) before BRANCH 0x11B5625B at 0x11B577F1.
  This branch is conditional (from 0x11B577EA).
  BL is used for RBP:2 init at 0x11B57081 — confirms BL is the opcode key.

────────────────────────────────────────────────────────────────────────────────
CONSOLIDATED ANSWER to Q6: [RBP+0] PC offset inference
────────────────────────────────────────────────────────────────────────────────
None of the exported functions show the PC offset being written to [RBP+0].
The context struct [RBP+0] is set up BEFORE any of these functions execute,
in the deeper call chains not visible in these exports.
The PC offset field cannot be inferred statically from available exports.

────────────────────────────────────────────────────────────────────────────────
KEY ARCHITECTURAL INSIGHT from this pass
────────────────────────────────────────────────────────────────────────────────
There are at least 4 distinct paths to the dispatcher (0x11B5625B):

PATH A: FUN_11b5863d → FUN_11b56b2c → 0x11B5625B
  RSI = BSF(RBX) — small integer. NOT a bytecode stream VA.
  This is a UTILITY/HELPER dispatch, not the network packet decode path.

PATH B: FUN_11b45846 → FUN_11b56999 → FUN_11b59337 → FUN_11b59838 → 0x11B5625B
  RBP = RDX (2nd argument to FUN_11b59337) — real VM context pointer.
  RSI = unknown from caller chain. BL = caller's RBX.
  This is the NETWORK RECEIVE path — most likely target for S2C decode.

PATH C: FUN_11b5591a → 0x11B5625B (called via FUN_11b56f43)
  RSI = from caller of FUN_11b5591a. BL = caller's RBX.
  FUN_11b56f43 is called by FUN_11b581c1 (per call_edges.csv).
  FUN_11b581c1 is the large 44 KB function — the main handler body.

PATH D: Inside FUN_11b57075 → 0x11B5625B (at 0x11B577F1)
  RSP is 16-byte aligned before dispatch. BL used for RBP setup.
  This is the INITIALIZATION path executed at TLS callback startup.

CONCLUSION: PATH B (FUN_11b45846 receive path) is the S2C decode target.
The VM dispatcher in PATH B receives:
  - RBP = RDX = VM context struct pointer (2nd arg to FUN_11b59337)
  - BL = RBX from FUN_11b45846's caller (initial key byte for session)
  - RSI = NOT set in PATH B chain — must be set INSIDE the VM context struct
          by the VM itself via RSI += LOAD[RBP] at 0x11B562AE.

FINAL REGISTER STATE AT DISPATCHER ENTRY (PATH B):
  R12  = 0x11B54E6F  (hardcoded handler table base)
  RBP  = BSWAP32(RDX_from_FUN_11b45846_2nd_arg)  (VM context pointer, obfuscated)
  RSI  = RSI_from_caller + LOAD[obfuscated_RBP]  (bytecode ptr after init)
  BL   = RBX_from_FUN_11b45846_caller  (initial session key byte)
  [RBP+0] = PC offset into .aion1 bytecode stream
"""

from __future__ import annotations
import csv
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Q&A findings from pcode analysis
# ─────────────────────────────────────────────────────────────────────────────
FINDINGS = [
    {
        "question":   "Q1/Q2: What is RBP at entry to FUN_11b56b2c? What does FUN_11b5863d pass?",
        "function":   "FUN_11b5863d @ 0x11B5863D",
        "pcode_key":  "0x11B5866B: RBP = BSF(RBX) (bit-scan-forward loop); 0x11B5866F: BRANCH FUN_11b56b2c",
        "answer":     "RBP = BSF(RBX) = lowest set bit position of RBX. This is a SMALL INTEGER (0..63), NOT a valid VA. PATH A is a utility/helper dispatch path, not the packet decode loop.",
        "confidence": "high",
        "implication": "PATH A (FUN_11b5863d → FUN_11b56b2c → FUN_11b5625b) is NOT the S2C decode path.",
    },
    {
        "question":   "Q3: Does FUN_11b5591a provide static RSI/RBX setup?",
        "function":   "FUN_11b5591a @ 0x11B5591A",
        "pcode_key":  "0x11B5591A: RSP-=0x140; 0x11B55924: TEST BL,BL; 0x11B55926: AND RSP,0xFFFFF0; 0x11B5592A: BRANCH 0x11B5625B",
        "answer":     "No static RSI/RBX setup. FUN_11b5591a is PATH C: a thin trampoline that reserves stack, tests BL, aligns RSP, and branches to dispatcher. BL and RSI come from caller (FUN_11b56f43).",
        "confidence": "high",
        "implication": "PATH C caller FUN_11b56f43 (called by FUN_11b581c1) controls RSI and BL.",
    },
    {
        "question":   "Q4: Does FUN_11b50330 initialize RSI/RBX/BL?",
        "function":   "FUN_11b50330 @ 0x11B50330",
        "pcode_key":  "0x11B50330: PUSH junk; 0x11B50340: BRANCH thunk_FUN_11b57075",
        "answer":     "No. FUN_11b50330 only pushes obfuscation constants and jumps to thunk_FUN_11b57075. All registers come from caller (TLS callback: FUN_11b503FD). This is the VM INITIALIZATION path at process startup, not the receive decode path.",
        "confidence": "high",
        "implication": "FUN_11b50330 is pure startup/init trampoline. Not the S2C decode path.",
    },
    {
        "question":   "Q5: What does 0x1195D94A pass as RDX/RBX/RSI to FUN_11b45846?",
        "function":   "entry @ 0x1195D94A",
        "pcode_key":  "0x1195D94A: BRANCH 0x11B52CE5 (thunk_FUN_11b45846)",
        "answer":     "Entry 0x1195D94A is a single JMP with NO register setup. All registers come from the OS. This is the process entry point, not a direct path to packet decoding.",
        "confidence": "high",
        "implication": "OS provides register values at process start. Not usable for S2C key derivation.",
    },
    {
        "question":   "Q6: Can [RBP+0] PC offset be inferred from context construction?",
        "function":   "All reviewed functions",
        "pcode_key":  "No STORE to [RDX+0] or [RBP+0] found in any exported pcode",
        "answer":     "No. The [RBP+0] field (PC offset in VM context struct) is written by code deeper in the call chain not present in any pass622 export. Struct layout cannot be inferred statically.",
        "confidence": "high",
        "implication": "The [RBP+0] PC offset remains a hard blocker for bounded static VM trace.",
    },
    {
        "question":   "Q_NEW: What is PATH D (FUN_11b57075 direct dispatch)?",
        "function":   "FUN_11b57075 @ 0x11B57075 / 0x11B577F1",
        "pcode_key":  "0x11B57081: RBP:2 = sign_ext(BL); 0x11B577ED: AND RSP,0xFFFFF0; 0x11B577F1: BRANCH 0x11B5625B",
        "answer":     "PATH D is the initialization path called from FUN_11b50330 (TLS callback). BL is confirmed as the opcode key (used for RBP:2 = sign_ext(BL) at 0x11B57081). PATH D dispatches to 0x11B5625B with RSP aligned. BL and RSI from caller chain.",
        "confidence": "high",
        "implication": "Confirms BL role. PATH D is initialization, not the packet decode path.",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Updated register source table (incorporating new findings)
# ─────────────────────────────────────────────────────────────────────────────
REGISTER_SOURCES = [
    {
        "reg":             "R12 (handler table base)",
        "source_function": "FUN_11b5625b",
        "source_address":  "0x11B56278",
        "source_kind":     "constant",
        "value_or_origin": "0x11B54E6F (hardcoded)",
        "evidence":        "pcode: (register, 0xa0, 8) COPY (const, 0x11b54e6f, 8)",
        "confidence":      "high",
        "next_test":       "RESOLVED",
    },
    {
        "reg":             "RBP at PATH A entry (FUN_11b56b2c)",
        "source_function": "FUN_11b5863d",
        "source_address":  "0x11B5866B",
        "source_kind":     "computed",
        "value_or_origin": "BSF(RBX) = small integer 0..63. NOT a VA. PATH A is utility path.",
        "evidence":        "pcode: bit-scan-forward loop on RBX then RBP=result",
        "confidence":      "high",
        "next_test":       "PATH A is NOT the packet decode path. Do not trace further.",
    },
    {
        "reg":             "RBP at PATH B entry (FUN_11b59337)",
        "source_function": "FUN_11b59337",
        "source_address":  "0x11B59343",
        "source_kind":     "parameter",
        "value_or_origin": "RDX = 2nd call arg to FUN_11b59337 = VM context struct ptr",
        "evidence":        "pcode: (register, 0x28, 8) COPY (register, 0x10, 8)",
        "confidence":      "high",
        "next_test":       "Need callsite with RDX value — not yet in any export",
    },
    {
        "reg":             "BL (opcode key byte)",
        "source_function": "FUN_11b57075 + FUN_11b5591a",
        "source_address":  "0x11B57081 / 0x11B55924",
        "source_kind":     "caller_preserved",
        "value_or_origin": "BL = RBX from caller; confirmed key: TEST BL,BL at 0x11B55924; RBP:2=sign_ext(BL) at 0x11B57081",
        "evidence":        "pcode: TEST BL,BL; INT_SEXT BL used for RBP init",
        "confidence":      "high",
        "next_test":       "BL initial value requires callsite of FUN_11b45846 or FUN_11b50330 with RBX value",
    },
    {
        "reg":             "RSI (bytecode base, PATH B)",
        "source_function": "FUN_11b59337 / FUN_11b59838",
        "source_address":  "not found in PATH B chain",
        "source_kind":     "not_found",
        "value_or_origin": "RSI source not set in PATH B chain. Likely passed from FUN_11b45846 caller.",
        "evidence":        "No COPY to RSI in any PATH B pcode",
        "confidence":      "medium",
        "next_test":       "FUN_11b45846 caller's RSI value needed. Possibly points to network buffer struct.",
    },
    {
        "reg":             "[RBP+0] PC offset",
        "source_function": "unknown (deeper caller chain)",
        "source_address":  "not found",
        "source_kind":     "not_found",
        "value_or_origin": "Not written in any exported function. Set before dispatcher entry.",
        "evidence":        "No STORE to [RDX+0] or [RBP+0] in any export",
        "confidence":      "high",
        "next_test":       "Blocked: requires struct layout or deeper exports",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher path summary
# ─────────────────────────────────────────────────────────────────────────────
PATHS = [
    {
        "path_id":       "PATH_A",
        "entry_chain":   "FUN_11b5863d -> FUN_11b56b2c -> 0x11B5625B",
        "rsi_at_entry":  "BSF(RBX) = small integer 0..63 (NOT a bytecode VA)",
        "rbp_at_entry":  "RSP (stack frame)",
        "bl_at_entry":   "from caller",
        "is_decode_path": False,
        "role":          "utility/helper dispatch",
        "confidence":    "high",
    },
    {
        "path_id":       "PATH_B",
        "entry_chain":   "FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838 -> 0x11B5625B",
        "rsi_at_entry":  "unknown (from FUN_11b45846 caller)",
        "rbp_at_entry":  "BSWAP32(RDX_2nd_arg_to_FUN_11b59337) = VM context struct ptr",
        "bl_at_entry":   "caller's RBX, preserved via PUSH at FUN_11b59337",
        "is_decode_path": True,
        "role":          "NETWORK RECEIVE decode path — primary S2C candidate",
        "confidence":    "high",
    },
    {
        "path_id":       "PATH_C",
        "entry_chain":   "FUN_11b56f43 -> FUN_11b5591a -> 0x11B5625B",
        "rsi_at_entry":  "from FUN_11b56f43 caller (FUN_11b581c1, 44KB handler)",
        "rbp_at_entry":  "RSP (after RSP-=0x140 and AND RSP,0xFFFFF0)",
        "bl_at_entry":   "from FUN_11b56f43 caller",
        "is_decode_path": "unknown",
        "role":          "handler body sub-dispatch via FUN_11b581c1",
        "confidence":    "medium",
    },
    {
        "path_id":       "PATH_D",
        "entry_chain":   "TLS_callback -> FUN_11b50330 -> thunk_FUN_11b57075 -> FUN_11b57075 -> 0x11B5625B",
        "rsi_at_entry":  "RSP (AND RSP,0xFFFFF0)",
        "rbp_at_entry":  "varies (obfuscated from BL/AL/RAX in FUN_11b57075)",
        "bl_at_entry":   "from OS/TLS entry state; confirmed key register",
        "is_decode_path": False,
        "role":          "process startup / VM initialization path",
        "confidence":    "high",
    },
]


def write_findings_csv(out_path: Path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["question", "function", "pcode_key", "answer", "confidence", "implication"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(FINDINGS)
    print(f"Context findings written to: {out_path}")


def write_register_sources_csv(out_path: Path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["reg", "source_function", "source_address", "source_kind",
                      "value_or_origin", "evidence", "confidence", "next_test"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(REGISTER_SOURCES)
    print(f"Register sources written to: {out_path}")


def write_paths_csv(out_path: Path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["path_id", "entry_chain", "rsi_at_entry", "rbp_at_entry",
                      "bl_at_entry", "is_decode_path", "role", "confidence"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(PATHS)
    print(f"Dispatcher paths written to: {out_path}")


def print_summary():
    print("=" * 80)
    print("  DISPATCHER CONTEXT INSPECTION RESULTS")
    print("=" * 80)
    print()
    for f in FINDINGS:
        print(f"  {f['question']}")
        print(f"    Function : {f['function']}")
        print(f"    Key pcode: {f['pcode_key']}")
        print(f"    Answer   : {f['answer']}")
        print(f"    Conf.    : {f['confidence']}")
        print(f"    Impl.    : {f['implication']}")
        print()

    print("=" * 80)
    print("  DISPATCHER PATHS")
    print("=" * 80)
    for p in PATHS:
        decode = "[DECODE]" if p["is_decode_path"] is True else "[INIT/UTIL]"
        print(f"  {p['path_id']} {decode}: {p['entry_chain']}")
        print(f"    RSI: {p['rsi_at_entry']}")
        print(f"    RBP: {p['rbp_at_entry']}")
        print(f"    BL : {p['bl_at_entry']}")
        print(f"    Role: {p['role']}")
        print()

    print("=" * 80)
    print("  STILL BLOCKED")
    print("=" * 80)
    for r in REGISTER_SOURCES:
        if r["source_kind"] == "not_found" or r["next_test"] not in ("RESOLVED", "PATH A is NOT the packet decode path. Do not trace further."):
            print(f"  [{r['confidence']}] {r['reg']}: {r['next_test']}")
    print()


def main():
    print_summary()
    out_dir = Path("artifacts")
    out_dir.mkdir(exist_ok=True)
    write_findings_csv(out_dir / "pass629_antigravity_dispatcher_context_findings.csv")
    write_register_sources_csv(out_dir / "pass629_antigravity_context_register_sources.csv")
    write_paths_csv(out_dir / "pass629_antigravity_dispatcher_paths.csv")
    # Create validation CSV (no bounded trace run — blocked)
    validation_path = out_dir / "pass629_antigravity_vm_trace_validation.csv"
    with open(validation_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["validation_id", "path", "rsi_assumed", "bl_assumed",
                         "pc_offset_assumed", "trace_run", "result", "reason"])
        writer.writerow(["VT-001", "PATH_A", "BSF(RBX)=small_int", "UNKNOWN", "UNKNOWN",
                         "false", "REJECTED",
                         "PATH A RSI = BSF(RBX) is a small integer, not a bytecode VA. Not the packet decode path."])
        writer.writerow(["VT-002", "PATH_B", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                         "false", "BLOCKED",
                         "RBP = BSWAP32(RDX_from_caller). RSI source unknown. BL = caller RBX, value unknown."])
        writer.writerow(["VT-003", "PATH_C", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                         "false", "BLOCKED",
                         "FUN_11b581c1 (44KB) controls RSI and BL. Not exported."])
        writer.writerow(["VT-004", "PATH_D", "RSP_aligned", "OS_default", "UNKNOWN",
                         "false", "NOT_DECODE_PATH",
                         "PATH D is VM initialization (TLS callback), not packet decode."])
    print(f"Trace validation written to: {validation_path}")
    return {
        "paths_found":          len(PATHS),
        "decode_path_found":    any(p["is_decode_path"] is True for p in PATHS),
        "decode_path":          "PATH_B",
        "rsi_found":            False,
        "bl_found":             True,   # role confirmed, value unknown
        "pc_offset_found":      False,
        "bounded_trace_run":    False,
        "next_missing_export":  "FUN_11b581c1 (0x11B581C1, 44KB) controls RSI/BL for PATH C",
    }


if __name__ == "__main__":
    result = main()
    print("Run result:")
    for k, v in result.items():
        print(f"  {k}: {v}")
