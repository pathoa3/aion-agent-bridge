# Antigravity Report: pass623 keyslot candidate review

## Status: REVIEW COMPLETE (3 candidates rejected)

An offline review of the first three S2C keyslot candidate functions was performed using exported disasm/pcode/decomp files from Ghidra. All three candidates were rejected as they do not initialize or write S2C keys.

---

## Candidates Reviewed

1. **P622-KS-002** (`0x11B559CD` / `FUN_11b559cd`)
   - **Type**: VM Stack/local scratch write
   - **Verdict**: **REJECT**
   - **Reason**: The store is a native `PUSH RAX` register preservation instruction.

2. **P622-KS-007** (`0x11B564BE` / `FUN_11b564be`)
   - **Type**: VM Stack/local scratch write
   - **Verdict**: **REJECT**
   - **Reason**: The stores are native register preservation `PUSH` instructions (including a static pointer push `PUSH qword ptr [0x11b592f1]`).

3. **P622-KS-008** (`0x11B57075` / `FUN_11b57075`)
   - **Type**: VM Stack/local scratch write
   - **Verdict**: **REJECT**
   - **Reason**: The stores are native register preservation `PUSH` instructions.

---

## Architectural Findings
The writes flagged by automated scans in these three functions are native stack `PUSH` operations (PCode `STORE (const, 0x1b1, 8)` to `RSP`). These are part of the VM interpreter's state saving before dispatching execution, and do not represent writes to a session context key structure.

Intermediate key and packet state are stored within the VM stack frame relative to `RBP` or `RDI` inside the VM handler loop, rather than written directly to a heap structure via native memory writes.
