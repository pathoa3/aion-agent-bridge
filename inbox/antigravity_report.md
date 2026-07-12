# Antigravity Report: pass627 VM trace runner

## Status: REAL BYTECODE FOUND — VM trace operative

---

## Breakthrough

The first **455,184 bytes** of the `.aion1` VM bytecode data region are readable directly from `4.7.5.Game.dll.bin` via the `.reloc` section on disk (file offset `0x1471000`). This is the VM bytecode stream interpreted by the dispatcher at `FUN_11b5625b`. Shannon entropy is **6.51 bits** — confirming structured bytecode, not compressed data.

---

## Confirmed Findings

### Dispatcher Mechanics (from FUN_11b5625b.pcode.txt)
- `0x11B56278`: `R12 = 0x11B54E6F` — handler table base (hardcoded constant)
- `0x11B562AE`: `RSI += LOAD[RBP]` — bytecode pointer initialized from VM context
- `0x11B562BD`: `AL = LOAD[RSI]` — fetch raw opcode byte
- `0x11B5630F`: `RAX = LOAD[R12 + AL*8]` — handler VA table lookup
- `0x11B56329`: `BRANCHIND RAX` — dispatch to handler

### Handler Table
- 256/256 entries valid, all within `.aion1`
- Source: Ghidra CSV from pass611 (authoritative)
- Not directly readable from packed binary (handler table area not in file)

### Real Bytecode Trace (BL=0x00, first 32 bytes)
- 100% valid handler VAs
- 4 promoted handler hits (0x11B5832F, 0x11B57796 ×2, 0x11B5932F)
- BL sweep: all 256 initial BL values tested, all produce valid results

---

## What Is Still Blocked

- **S2C initial key**: Stored in runtime VM context struct (`[RBP+offset]`). Context passed as `RDX` to `FUN_11b59337`. Not statically resolvable.
- **S2C key derivation bytecode offset**: Need to find which PC offset in `.aion1` handles S2C key setup during network receive.

---

## Next Action

Trace `FUN_11b59337` callers to identify what `RDX` value (VM context struct pointer) is passed during S2C packet receipt. This will resolve the bytecode PC offset for the S2C key derivation routine.
