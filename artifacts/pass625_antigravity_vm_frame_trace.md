# pass625 Antigravity VM Frame Trace

This document summarizes the tracing of VM-frame state and register mapping inside the EuroAion VM interpreter.

---

## Architectural Finding: Register-Mapped VM Interpreter

Static analysis of P-code, disassembly, and decompiler output reveals that the VM interpreter does not use a traditional context structure with offset-based variables in memory. Instead, it is a **Register-Mapped VM Interpreter**:
1. Virtual registers and state variables (including key bytes and bytecode pointers) are mapped directly to native CPU registers during interpreter execution.
2. The interpreter handlers are flattened and obfuscated, tail-calling each other or thunking back to the dispatcher.

### Key Registers Mapped:
- **`RBP` (Base Pointer)**: VM Context Pointer.
- **`RBP + 0x00` (Memory Offset)**: VM Program Counter (PC) offset. Added to `RSI` to compute current bytecode address.
- **`RSI` (Source Index)**: VM Bytecode Instruction Pointer (current memory address of instruction).
- **`RBX` (specifically `BL`)**: Opcode Decoding Key / Rolling Key byte. Used to decode bytecode opcodes.
- **`R12` (Base register)**: VM Handler Table Base (points to static table at `0x11B54E6F`).
- **`RDX` (Destination register)**: VM Handler address (loaded from table and jumped to indirectly).

---

## VM-Frame and Context Variable Map

The scan of the P-code and disassembly confirms that offset memory accesses to the context structure are extremely minimal. The VM manages its virtual registers directly in native registers:

| Base Register | Offset / Register | Access | Candidate Role | Evidence | Confidence |
|---|---|---|---|---|---|
| `RBP` | `0x00` | LOAD | VM PC Offset | `ADD RSI, qword ptr [RBP]` inside `FUN_11b5625b` | High |
| `RBX` | `BL` | READ | Opcode Decryption Key | `SUB AL, BL` inside `FUN_11b5625b` | High |
| `RSI` | `[RSI]` | LOAD | Bytecode Instruction Fetch | `MOV AL, byte ptr [RSI]` inside `FUN_11b5625b` | High |
| `R12` | `[R12 + RAX*8]` | LOAD | Handler Address Lookup | `MOV RDX, qword ptr [R12 + RAX*8]` inside `FUN_11b5625b` | High |

---

## Key Setup Path Blockers

Because the VM uses registers and interpreted bytecode rather than compiled native stores, we cannot find a native "keyslot write" function for the S2C key. 

To resolve the S2C initial key setup:
1. **Network Handler Entry**: The receive path thunks from `FUN_11b45846` (network receiver loop) -> `FUN_11b59337` -> `FUN_11b59832` (decryption wrapper).
2. **Interpreter Invocation**: `FUN_11b59832` invokes the VM interpreter dispatcher `FUN_11b5625b` with the packet buffer.
3. **Bytecode Tracing Needed**: We must analyze the interpreted VM bytecode instructions inside the `.aion1` section to see how the S2C key register is initialized when the S2C handshake packet (frame 4094) is parsed.
