# Pass610 Antigravity VM Table Progress

We verified the Ghidra-extracted VM table base, handler mapping, and unique handler addresses:

## 1. Verified Properties
- **Table Base Address:** `0x11B54E6F`.
- **Add Constant:** `0x15F664FE`.
- **Formula:** `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE`.
- **Total Mapped Opcodes:** 256.
- **Unique Handlers:** 70.
- **Handlers of Interest:**
  - `0x11B57796` (Opcodes `113, 120, 157, 187, 231, 247` - 6 occurrences).
  - `0x11B5932F` (Opcodes `132, 160, 208, 235` - 4 occurrences).
- **Redundant Handlers:** The high density of shared handler addresses confirms VM design reuse across opcodes.
