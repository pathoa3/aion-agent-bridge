# Antigravity Report: pass626 VM bytecode trace

## Status: TOOLING CREATED – VM entry context mapped

Offline VM bytecode trace plans and simulation tooling have been built under `tools/pass626_antigravity_vm_bytecode_trace/`. All VM entry context variables (`RBP`, `RSI`, `BL`) have been traced and mapped.

---

## VM Entry Context Mapped
1. **RBP (VM Context Pointer)**: Overwritten with `RDX` (the second x64 argument) in `FUN_11b59337` via `MOV RBP, RDX`.
2. **RSI (Bytecode Pointer)**: Offset loaded from `[RBP]` via `ADD RSI, qword ptr [RBP]` inside `FUN_11b5625b` dispatcher.
3. **BL/RBX (Opcode Decryption Key)**: Passed directly in the `RBX` register from the caller. Used to decrypt raw bytecode via `SUB AL, BL` inside dispatcher.

---

## Deliverables Created
1. `tools/pass626_antigravity_vm_bytecode_trace/extract_vm_entry_context.py` - Static extraction steps.
2. `tools/pass626_antigravity_vm_bytecode_trace/trace_vm_bytecode_skeleton.py` - Simulation loop that decodes raw bytes and maps them to Ghidra handlers.
3. `tools/pass626_antigravity_vm_bytecode_trace/README.md` - Technical overview.

---

## Next Steps
Use the simulation skeleton to trace bytecode execution of the S2C handshake (frame 4094) under different initial `BL` key candidates, identifying the handlers that execute during the S2C key initialization.
