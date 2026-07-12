# pass626 VM Bytecode Trace Tooling

Static/offline tools to trace VM bytecode execution path around the receive/decryption wrapper.

No live process, no injection.

---

## Files

| File | Purpose |
|---|---|
| `extract_vm_entry_context.py` | Extracts the step-by-step register mapping for `RBP` (context), `RSI` (bytecode), and `BL` (key) during receive path VM entry. |
| `trace_vm_bytecode_skeleton.py` | Simulates decoding raw bytecode bytes to resolve them to handler VAs from Ghidra. |
| `README.md` | This file. |

---

## VM Entry Setup Flow

When a network packet is received, the call chain is:
`FUN_11b45846` -> `FUN_11b59337` -> `FUN_11b59832` -> `FUN_11b5625b` (dispatcher).

1. **RBP (VM Context Pointer)**: Mapped from `RDX` (the second function parameter) in `FUN_11b59337`.
2. **RSI (Bytecode Pointer)**: Initialized as `Bytecode Base + [RBP]` (which loads the VM PC offset).
3. **BL/RBX (Decryption Key)**: Passed directly in `RBX` register from the native caller.
4. **R12 (Handler Table Base)**: Set to `0x11B54E6F`.

---

## Run trace simulator

```cmd
cd tools/pass626_antigravity_vm_bytecode_trace
python trace_vm_bytecode_skeleton.py
```
This runs the simulation over a sample bytecode stream, decoding raw bytes using the rolling `BL` formula, and looking up their resolved VM handlers from the `pass8b_handler_table_from_ghidra.csv` database.
