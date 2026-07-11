# Pass610 VM Emulation Plan

## Safe Scope
Build a text-export-driven emulator only. Do not execute the client, attach to a process, dump memory, inject, or use runtime unpacking.

## Minimum Emulator Model
- Parse `pass8b_handler_table_from_ghidra.csv` for opcode-to-handler mapping.
- Parse `pass8b_target_pcode.txt` by address/range into p-code operations.
- Implement VM state fields for instruction pointer (`RSI` candidate), rolling decode byte (`BL`), handler table base (`R12` candidate), and an abstract register/stack file.
- Implement opcode decode from the current note: `rol8(((raw - BL + 0x86) ^ 0x34), 5)` and `BL = (BL - opcode) & 0xff`.
- Dispatch to parsed handler p-code summaries and record high-level effects: loads, stores, arithmetic, table lookups, branches, and external calls.

## Required Inputs Missing Now
- `pass8b_handler_table_from_ghidra.csv` with all 256 resolved handlers.
- `pass8b_target_pcode.txt` with handler and dispatcher p-code.
- `pass8b_target_disassembly.txt` and `pass8b_target_flows.csv` to resolve branches/fallthroughs.
- A bounded bytecode slice or file-backed VM instruction stream region to feed the opcode decoder.
- A proven packet buffer pointer/length field mapping, or enough p-code to discover it statically.

## Next Smallest Testable Unit
Regenerate the Ghidra text exports and run `parse_vm_table.py` plus `classify_handlers.py` against them. The first concrete test is whether reported handler groups `0x11B57796` and `0x11B5932F` contain byte load/store plus xor/add/shift patterns or are only dispatcher/control-flow handlers.
