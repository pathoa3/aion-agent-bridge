# pass623 Antigravity Keyslot Candidate Review

This document contains the review of the first three S2C keyslot candidate functions identified in pass622:
1. **P622-KS-002** (`0x11B559CD` / `FUN_11b559cd`)
2. **P622-KS-007** (`0x11B564BE` / `FUN_11b564be`)
3. **P622-KS-008** (`0x11B57075` / `FUN_11b57075`)

---

## Detailed Analysis

### 1. Candidate P622-KS-002
- **Function Entry**: `0x11B559CD` (`FUN_11b559cd`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: `RAX` register (`PUSH RAX`).
- **Seed/Key Arithmetic Source**: None. It is a simple register preservation push.
- **Reachable from Handshake Path**: Yes, it thunks to `FUN_11b59838` which directly enters dispatcher `FUN_11b5625b`.
- **Verdict**: **REJECT**. 
- **Rationale**: The store identified by static scanning is a native `PUSH RAX` instruction at the function's entry point used to preserve register state before executing VM junk instructions. It does not write to a global or heap key context.

---

### 2. Candidate P622-KS-007
- **Function Entry**: `0x11B564BE` (`FUN_11b564be`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: Registers `RDX`, `RDI`, `RBX`, `RAX` via standard pushes, and a static QWORD read from the `.aion1` section: `PUSH qword ptr [0x11b592f1]`.
- **Seed/Key Arithmetic Source**: None.
- **Reachable from Handshake Path**: Yes, it thunks to `FUN_11b5586b` -> `FUN_11b56696` -> dispatcher `FUN_11b5625b`.
- **Verdict**: **REJECT**.
- **Rationale**: The function is a VM handler/dispatcher block that uses `PUSH` instructions (including a static pointer push from `.aion1`) to manage its stack layout. No key writes are present.

---

### 3. Candidate P622-KS-008
- **Function Entry**: `0x11B57075` (`FUN_11b57075`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: Registers `RBP`, `R9`, `R10`, `RCX`, `R14`, `R8` via standard pushes.
- **Seed/Key Arithmetic Source**: None.
- **Reachable from Handshake Path**: Yes, thunks/jumps to other VM handlers and dispatcher `FUN_11b5625b`.
- **Verdict**: **REJECT**.
- **Rationale**: This is a dispatcher entry thunk that preserves CPU registers on the native stack before branching. It performs no key storage or arithmetic writes.

---

## Architectural Conclusion
The static writes flagged by automated scans in these candidates are all CPU register preservation instructions (`PUSH`) writing to the native stack (`0x1b1` space relative to `RSP`). 

This confirms that the VM does not write rolling keys to a separate session context structure via native stores in these dispatcher entries. Instead, the keys and intermediate state are stored in the VM stack frame relative to `RBP` or `RDI` inside the VM handler loop.
