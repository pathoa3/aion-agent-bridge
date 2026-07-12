# Pass611 Codex Ghidra Follow-up

Codex generated the missing Ghidra exports locally under the private outbox. The raw p-code/disassembly/export files were **not** copied into Git artifacts.

## New Static Evidence

- `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, and handler-table exports now exist locally.
- Dispatcher decode is confirmed from Ghidra output: fetch `[RSI]`, decode with `BL`, update `BL`, increment `RSI`, and table-dispatch via `R12 + RAX*8`.
- Handler `0x11B57796` is refined: it reads `EAX` from `[RSI]` and jumps to dispatcher continuation at `0x11B56580`. This is consistent with loading a VM bytecode operand/immediate, not directly decrypting packet payload bytes.
- P609-012 `0x114731E0..0x114731F5` was not covered by the new target/recursive export slices, so the previous rejection stands; it is not a usable transform source.

## Decoder Status

No handler-derived packet transform was tested in this follow-up because the new semantics still do not connect a handler to packet buffer writes. No exact plaintext was recovered and no decoder success is claimed.

## Remaining Blocker

Ghidra p-code proves the VM opcode dispatcher and refines 0x11B57796 as a VM bytecode dword-load/stack materialization path, but no native bridge from VM state to packet payload buffer writes is present in the exported slices. Need the VM bytecode program slice or a native flow slice that reaches candidate packet buffer writes from confirmed context fields.

## Next Step

Trace from native call sites that initialize RSI/RBP/R12/R13 for the VM and locate memory writes to candidate packet buffer/length fields; alternatively provide a file-backed VM bytecode slice so the dispatcher can be symbolically interpreted across real opcodes.
