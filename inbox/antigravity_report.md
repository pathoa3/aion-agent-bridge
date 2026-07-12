# Antigravity Report: pass625 VM frame trace

## Status: TRACE COMPLETE – VM variables mapped

An offline trace of RBP/RDI context memory access was performed across all exported P-Code and disassembly files for the dispatcher and candidate functions. 

---

## Architectural Findings

1. **Register-Mapped VM State**:
   - The VM does not maintain S2C/C2S keys in static global variables or dedicated native heap structures.
   - Virtual registers and keys are mapped directly to native CPU registers during interpreter execution.
   - The rolling key byte is held in register `BL` (native `RBX` register) during opcode fetch and instruction execution.

2. **Dispatcher Context Offset**:
   - `RBP` points to the VM context structure on the stack.
   - `[RBP]` (offset `0x00`) holds the VM PC offset, which is added to `RSI` (the bytecode pointer) during instruction dispatch (`0x11B562AE ADD RSI, qword ptr [RBP]`).

3. **General Handlers**:
   - All instruction handlers (`FUN_11b57075`, `FUN_11b581c1`, etc.) perform arithmetic calculations on the native registers.
   - These represent updates to virtual registers (including rolling keys) under a control-flow flattened/obfuscated assembly layer.

---

## Next Steps to Break the Blocker
Since the key initialization logic is implemented in interpreted VM bytecode rather than native compiled code, native scanning will not yield the S2C key. 

We need to analyze the interpreted VM bytecode inside the `.aion1` section. Specifically, tracing the execution path starting from the network packet receipt hook (`FUN_11b59337` -> `FUN_11b59832`) when the handshake packet (frame 4094) is received will show how the initial S2C key virtual register is initialized.
