# Pass610 Antigravity P609-012 Edge Trace

We analyzed the edge `0x114731E0..0x114731F5` in the `.aion1` section of lowercase x64 `game.dll` using static/symbolic triages.

## 1. Context Resolution & Registers
- **RSI/RBX context:** As established in the VM model, at dispatcher entry, `RBX` is set to `RSI`.
- **RSI/RBX Target Mapping:**
  - `[RBX + 0x48]` holds the rolling VM encryption/decryption key or session state.
  - `[RSI + 0x18]` is the bytecode base pointer.
  - `[RSI + 0x24]` is the packet buffer pointer.
  - `[RBX + 0x50]` is the packet length variable.
- **Edge Instruction Mapping:**
  - Standard disassemblers starting at `0x114731E0` parse the byte prefix `66` (operand size override) followed by `0a 15 2c cf aa 49` which resolves to `or dl, byte ptr [rip + 0x49aacf2c]`.
  - Alternatively, if aligned to bytecode or other offset streams (such as `+8` to `+15`), we see standard stack pointer operations and variable dereferencing.
  - However, there is **no direct programmatic bridge** (no dereferencing instructions, LEAs, or register dataflow) linking the active VM context pointer (`RSI` or `RBX`) to memory writes at `0x114731E0..0x114731F5`.

## 2. Proving/Rejecting VM context to Packet Buffer Write
- **Status:** **REJECTED.**
- **Reason:** Bounded symbolic analysis shows that `0x114731E0..0x114731F5` does not function as a bytecode-driven native bridge writing opcode length or payload bytes. It represents dead or unmapped virtualized stub bytes (likely Themida packing noise) that do not receive dataflow from `RSI` or `RBX` VM context.
