# Pass635 Recv Wrapper Audit

## Status: STATIC PATH EXHAUSTED — FUTURE S2C ORACLE IS BEST NEXT STEP

---

## Pass634 Export Failure Root Cause

The `export_recv_import_wrappers.java` script saved by pass634 had a **UTF-8 BOM** (`EF BB BF`) prepended.  
Ghidra's headless Java compiler treats the BOM as an illegal character (`\ufeff`), causing:

```
export_recv_import_wrappers.java:1: error: illegal character: '\ufeff'
?// Ghidra Java script: ...
^
GhidraScriptLoadException: The class could not be found.
```

**Result:** No CSV, pcode, or decompile output was produced. The pass634 export folder contained only the log file.

**Fix applied for pass635:** Saved the Java script as UTF-8 without BOM. Ghidra ran successfully (exit 0).

---

## Pass635 Ghidra Export Results

Script: `export_recv_import_wrappers.java` (fixed, no BOM)  
Output: `C:\AionTools\aion_decoder_agent\outbox\pass635_recv_wrappers\`  
Exit code: **0 (success)**

| File | Rows | Meaning |
|---|---|---|
| `recv_import_symbols.csv` | 9 rows | All WS2_32 socket APIs found |
| `recv_import_xrefs.csv` | 9 rows | All xrefs — all `DATA` type |
| `recv_wrapper_edges.csv` | **0 rows (header only)** | No call edges from any wrapper |
| `recv_wrapper_functions.csv` | **0 rows (header only)** | No wrapper functions found |

---

## Definitive Finding: Why No Recv Callers Are Visible

Every reference to `recv`, `WSARecv`, `recvfrom` (and all other socket APIs) is of type **`DATA`** — meaning Ghidra's reference manager found only the **IAT pointer slot address** (`0x119FD040`, `0x119FD108`, etc.) being stored in the import table, but **zero code-level CALL or BRANCH references** pointing at those IAT entries.

### The Architectural Reason

The `CALL QWORD PTR [RIP+rel32]` instructions that invoke `WSARecv` reside in the **protected `.aion1` section** (VA range `0x11472000..0x11B59A00`). This section:

1. Is **packed/compressed** — the upper portion above `0x114E2000` (~7.4 MB of 7.7 MB) cannot be statically disassembled by Ghidra  
2. Contains **VM-protected code** with custom dispatch — Ghidra's control-flow analysis cannot trace through the VM handler dispatch chain  
3. Has no Ghidra-recognized function bodies in the packed region — so `getFunctionContaining(fromAddress)` returns `null` for every IAT reference site

This is not a tooling failure. It is the **design of the protection**: socket calls are made from within packed, VM-protected code that standard static analysis cannot reach.

### Binary-Level Confirmation

Direct search of the packed PE binary (`euroaion/4.7.5.Game.dll.bin`, 20.88 MB) for 4-byte LE patterns of all IAT RVAs and absolute addresses returned **zero hits** — confirming the caller code is in an unrecovered packed region.

---

## Call/Xref Graph: No Path from Recv Wrappers to Path B

```
recv / WSARecv / recvfrom
        |
        | (IAT slot only, DATA ref)
        |
        [PACKED .aion1 CODE - not visible to Ghidra]
        |
        ? unknown dispatch chain ?
        |
   FUN_11b45846  <-- Path B entry (known, exported)
        |
   FUN_11b56999 -> thunk_FUN_11b59337 -> FUN_11b59337
        |
   FUN_11b59832 / FUN_11b59838
        |
   FUN_11b5625b (VM dispatcher)
```

**No static path** from recv → Path B has been established or can be established with current tools.

---

## Why is the Static Path Exhausted?

| Check | Result |
|---|---|
| Ghidra xref DB for recv/WSARecv code callers | 0 callers — all DATA refs only |
| Packed binary IAT ref scan | 0 hits — callers in packed region |
| Pass634 callgraph (111 edges, 6 unique Path B predecessors) | No recv-related predecessor |
| Context struct [RBP+0] write | Not found in any export |
| Initial BL value | Not traceable statically |
| RSI base at Path B entry | Not set in any exported function |

All available static/offline export evidence is now exhausted.

---

## Path B Intersections Found

**0** — No recv wrapper reaches Path B in any currently-available static export.

---

## Future S2C Oracle: Best Next Step

The `future_s2c_oracle_scaffold.py` (pass634) is ready. The oracle route bypasses the static blocker entirely by working from a **known-plaintext S2C frame** instead of reverse-engineering the key from the VM dispatch chain.

### What the oracle needs

1. A **frame number** of an S2C packet with known plaintext content  
   - Best candidate: the world-entry SM_VERSION packet (always first S2C after connection)  
   - Or: the MOTD/login banner which contains a predictable string
2. The **exact UTF-16LE plaintext** of a field in that packet  
3. The **raw encrypted S2C payload bytes** from the PCAP

### Why the oracle bypasses all static blockers

- No need to know RDX, RSI, [RBP+0], or initial BL  
- The cipher stream is derived empirically from plaintext XOR ciphertext  
- Key update formula `BL = (BL - opcode) & 0xFF` is already confirmed  
- The stream cipher is a simple rolling XOR with known update rule

### Oracle procedure (when ready)

```python
# Recover keystream from known-plaintext frame:
keystream = [p ^ c for p, c in zip(known_plaintext, ciphertext)]
# First byte of keystream reveals the effective BL at that packet position
initial_bl_candidate = keystream[0]
# Roll forward from there for all subsequent S2C packets
```

This approach has already worked for C2S (11/11 KXSEQ, pass616).  
The S2C version requires only a known-plaintext frame anchor.
