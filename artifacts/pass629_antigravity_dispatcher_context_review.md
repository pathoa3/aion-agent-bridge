# pass629 Dispatcher Context Review

## Status: 4 DISPATCHER PATHS MAPPED — PATH B CONFIRMED AS S2C DECODE PATH

---

## Key Discovery: All "Missing" Exports Were Already Present

All 4 previously-identified missing functions (`FUN_11b5863d`, `FUN_11b5591a`, `FUN_11b50330`, `0x1195D94A`) were already present in the pass622 export directory. No new Ghidra export was needed.

---

## Q&A Results

| Question | Answer | Confidence |
|---|---|---|
| **Q1/Q2**: RBP at FUN_11b56b2c entry? | `RBP = BSF(RBX)` = small integer 0..63. **PATH A is utility, NOT decode.** | high |
| **Q3**: FUN_11b5591a static RSI/RBX? | No. Thin trampoline: reserves stack, tests BL, aligns RSP, branches to dispatcher. Caller controls RSI/BL. | high |
| **Q4**: FUN_11b50330 initializes RSI/RBX/BL? | No. Pure junk-push + JMP to thunk_FUN_11b57075. VM init path at TLS startup. | high |
| **Q5**: 0x1195D94A args to FUN_11b45846? | Single JMP only. No register setup. OS provides all register values. | high |
| **Q6**: [RBP+0] PC offset inferable? | No. Not written in any exported function. Hard blocker remains. | high |

---

## Four Dispatcher Entry Paths

```
PATH A [UTILITY]:  FUN_11b5863d → FUN_11b56b2c → 0x11B5625B
  RSI = BSF(RBX) = bit_scan_forward(RBX) = small integer 0..63
  NOT a bytecode VA. This is a helper dispatch path.

PATH B [DECODE]:   FUN_11b45846 → FUN_11b56999 → FUN_11b59337 → FUN_11b59838 → 0x11B5625B
  RBP = BSWAP32(RDX) where RDX = 2nd arg to FUN_11b59337
  BL  = caller's RBX (preserved via PUSH at FUN_11b59337 entry)
  RSI = unknown from caller chain
  *** PRIMARY S2C CANDIDATE ***

PATH C [HANDLER]:  FUN_11b56f43 → FUN_11b5591a → 0x11B5625B
  Called from FUN_11b581c1 (44KB main handler body)
  RSI and BL controlled by FUN_11b581c1/FUN_11b56f43

PATH D [INIT]:     TLS_callback → FUN_11b50330 → FUN_11b57075 → 0x11B5625B
  BL confirmed as opcode key (RBP:2 = sign_ext(BL) at 0x11B57081)
  Process startup initialization, not packet decode
```

---

## BL Role Fully Confirmed

Multiple pcode sites confirm `BL` (register 0x18, size 1) as the **opcode decryption key**:
- `FUN_11b5591a @ 0x11B55924`: `TEST BL, BL` (used as condition)
- `FUN_11b57075 @ 0x11B57081`: `RBP:2 = sign_ext(BL)` (key value drives dispatch)
- `FUN_11b5625b @ 0x11B562CC`: `AL = AL - BL` (core decode step)

---

## Still Blocked

| Blocked Item | Why | Export Needed |
|---|---|---|
| RDX actual value (PATH B) | Runtime arg to FUN_11b59337 | Callsite of FUN_11b45846 with RDX |
| RSI base (PATH B) | Not set in PATH B chain | FUN_11b45846 caller RSI value |
| `[RBP+0]` PC offset | Context struct field, not in any export | Context struct layout |
| BL initial value | From OS/TLS caller — not in any export | OS call context |

---

## Next Action: FUN_11b581c1 (44KB)

`FUN_11b581c1` (`0x11B581C1`) is the 44 KB main VM handler body that controls RSI and BL for PATH C. Per `call_edges.csv`:
- `FUN_11b581c1 → FUN_11b56f43 → FUN_11b5591a → 0x11B5625B`

Its pcode file is already exported: `11B581C1_FUN_11b581c1.pcode.txt` (44 KB). Inspecting it may reveal:
1. How RSI is set before the sub-dispatch
2. Whether BL is set to a concrete initial value
3. Whether the context struct layout (`[RBP+0]`) is written here
