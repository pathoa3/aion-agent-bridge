# Antigravity Report: pass624 remaining keyslot candidate review

## Status: ALL CANDIDATES EVALUATED & REJECTED

All 6 remaining S2C keyslot candidate functions identified in pass622 have been reviewed offline using exported disasm/pcode/decomp files from Ghidra. All candidates are rejected.

---

## Candidates Reviewed

1. **P622-KS-001** (`0x11B5863D` / `FUN_11b5863d`) - **REJECT**. Native stack `PUSH` only.
2. **P622-KS-004** (`0x11B581C1` / `FUN_11b581c1`) - **REJECT**. Native stack `PUSH` only.
3. **P622-KS-005** (`0x11B57BDB` / `FUN_11b57bdb`) - **REJECT**. Native stack `PUSH` only.
4. **P622-KS-006** (`0x11B56B2C` / `FUN_11b56b2c`) - **REJECT**. No writes (dispatcher thunk).
5. **P622-KS-009** (`0x11B59765` / `FUN_11b59765`) - **REJECT**. Native stack `PUSH` only.
6. **P622-KS-010** (`0x11B58D6C` / `FUN_11b58d6c`) - **REJECT**. Native stack `PUSH` only.

---

## Architectural Findings & Conclusion

All memory writes flagged by automated PCode analysis across all 10 candidates are native stack writes (`STORE` to space `0x1b1` relative to `RSP`), corresponding to standard `PUSH` instructions. 

This confirms the VM architecture:
- **No Native Keyslot Structure**: There is no dedicated heap structure or global variable for the S2C key initialization code inside these dispatcher entries.
- **VM-Frame Storage**: S2C session key state is maintained entirely within the VM context frame as local stack variables (referenced via `RBP` or `RDI` relative offsets).
- **Ambiguity Block**: Because the VM context variables are dynamically initialized and updated through interpreted bytecode instructions rather than native compiled code, S2C key setup cannot be resolved from native compiled function scanning.
