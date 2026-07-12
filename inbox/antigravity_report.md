# Antigravity Report: pass628 Dispatcher Entry Register Trace

## Status: REGISTER SOURCES MAPPED — KEY BLOCKERS IDENTIFIED

---

## What Was Done

Traced all 7 locally exported Ghidra pcode files through both VM dispatcher entry paths:
- `FUN_11b45846`, `FUN_11b566dd`, `FUN_11b56999` (PATH B network receive chain)
- `FUN_11b59337`, `FUN_11b59838` (PATH B context/wrapper)
- `FUN_11b56b2c` (PATH A direct dispatch)
- `FUN_11b5625b` (dispatcher)

---

## Confirmed Register Sources

| Register | Source | Evidence |
|---|---|---|
| **R12** (handler table) | `0x11B54E6F` — hardcoded constant | `0x11B56278` pcode |
| **RSI** (PATH A) | `RSI = RBP` at `0x11B56B4B` in `FUN_11b56b2c` | pcode COPY reg0x30=reg0x28 |
| **RBP** (PATH B) | `RBP = RDX` (2nd call arg) at `0x11B59343` | pcode COPY reg0x28=reg0x10 |
| **BL** | Caller's RBX, PUSH-preserved at `FUN_11b59337` entry | pcode STORE RSP, RBX |
| **Decode formula** | `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)` | pcode confirmed |

---

## Blocked Items

| Item | Why Blocked | Export Needed |
|---|---|---|
| RDX actual value (PATH B) | Runtime argument | pcode of entry caller (0x1195D94A) |
| RSI base (PATH B) | Not set in any exported PATH B function | N/A |
| `[RBP+0]` PC offset | Runtime context struct field | Context struct definition |
| Initial BL value | Caller of FUN_11b45846 chain not exported | FUN_11b50330 / entry thunk pcode |
| PATH A RBP at FUN_11b56b2c entry | Not exported | FUN_11b5863d pcode |

---

## Next Action

Export Ghidra pcode for:
1. `FUN_11b5863d` (`0x11B5863D`) — to get PATH A RSI base (RBP at FUN_11b56b2c entry)
2. `FUN_11b50330` (`0x11B50330`) — TLS callback path that may set RSI/RBX statically
3. Entry thunk `0x1195D94A` — to get RDX at FUN_11b45846 callsite (PATH B context pointer)
