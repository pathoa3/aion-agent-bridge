# pass624 Antigravity Remaining Keyslot Review

This document contains the review of the remaining six S2C keyslot candidate functions identified in pass622:
1. **P622-KS-001** (`0x11B5863D` / `FUN_11b5863d`)
2. **P622-KS-004** (`0x11B581C1` / `FUN_11b581c1`)
3. **P622-KS-005** (`0x11B57BDB` / `FUN_11b57bdb`)
4. **P622-KS-006** (`0x11B56B2C` / `FUN_11b56b2c`)
5. **P622-KS-009** (`0x11B59765` / `FUN_11b59765`)
6. **P622-KS-010** (`0x11B58D6C` / `FUN_11b58d6c`)

---

## Detailed Analysis

### 1. Candidate P622-KS-001
- **Function Entry**: `0x11B5863D` (`FUN_11b5863d`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: `RDX`, `RDI`, `RBX` registers via `PUSH`, and static QWORD `PUSH qword ptr [0x11b592f1]`.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: Yes.
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes (called via thunk chain `FUN_11b57075` -> `FUN_11b57bdb` -> `FUN_11b5863d`).
- **Verdict**: **REJECT**.
- **Rationale**: Confirmed native `PUSH` register preservation at entry.

### 2. Candidate P622-KS-004
- **Function Entry**: `0x11B581C1` (`FUN_11b581c1`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: Multiple registers preserved on stack (RDI, R13, R11, RAX, R12, R15, RSI, RDX, RDI, RBX, RAX) via PUSH.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: Yes.
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes (called via `FUN_11b57075` -> `FUN_11b57bdb` -> `FUN_11b5863d` -> `FUN_11b56b2c` -> `FUN_11b57075` -> `FUN_11b57bdb` -> `FUN_11b581c1`).
- **Verdict**: **REJECT**.
- **Rationale**: Confirmed native `PUSH` register preservation.

### 3. Candidate P622-KS-005
- **Function Entry**: `0x11B57BDB` (`FUN_11b57bdb`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: `RBP` register via PUSH.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: Yes.
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes (directly called from `FUN_11b57075`).
- **Verdict**: **REJECT**.
- **Rationale**: Confirmed native `PUSH` register preservation.

### 4. Candidate P622-KS-006
- **Function Entry**: `0x11B56B2C` (`FUN_11b56b2c`)
- **Store Destination**: None (no native stores).
- **Store Source**: None.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: No (only thunks directly to dispatcher `FUN_11b5625b`).
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes.
- **Verdict**: **REJECT**.
- **Rationale**: Contains no writes, simply performs bitwise check and thunks to the dispatcher.

### 5. Candidate P622-KS-009
- **Function Entry**: `0x11B59765` (`FUN_11b59765`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: `RDI` register via PUSH.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: Yes.
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes (directly called from `FUN_11b57075`).
- **Verdict**: **REJECT**.
- **Rationale**: Confirmed native `PUSH` register preservation.

### 6. Candidate P622-KS-010
- **Function Entry**: `0x11B58D6C` (`FUN_11b58d6c`)
- **Store Destination**: Native stack frame space (`0x1b1` space at `RSP`).
- **Store Source**: Registers `R13`, `R11`, `RAX`, `R12`, `R15`, `RSI`, `RDX`, `RDI` via PUSH.
- **Seed/Key Arithmetic Source**: None.
- **RSP Stack Store**: Yes.
- **Reachable from 0x11B56C63 / FUN_11b50330**: Yes (called via `FUN_11b57075` -> `FUN_11b59765` -> `FUN_11b58d6c`).
- **Verdict**: **REJECT**.
- **Rationale**: Confirmed native `PUSH` register preservation.

---

## Caller/Callee Trace Context
- `0x11B56C63` (thunk_FUN_11b57075) -> thunks to `FUN_11b57075`.
- `FUN_11b50330` -> thunks to `thunk_FUN_11b57075`.
- `0x11B5625B` / `FUN_11b5625b` -> the VM dispatcher, which invokes all these handler functions.

The entire call graph consists of a set of mutual thunk loops/tail-calls that return execution back to the VM dispatcher. This confirms that these functions represent the interpreter execution loop of the VM, not traditional native protocol handlers.

## Architectual Insight on S2C Key Storage
Since all native memory write candidates have been confirmed as register preservation pushes on the native CPU stack (`RSP`), we conclude that **there is no static native keyslot or heap/global structure used for S2C keys**. 

Instead, the VM context (addressed relative to register bases `RBP` or `RDI`) maintains the virtual registers and local frame variables. The rolling S2C key is held in this VM context frame on the native stack, which is updated dynamically inside the VM handler loop.
