# Pass622 Codex Deep S2C Static Trace Notes

## What Advanced Beyond Pass621

This pass inventoried text/static material directly and identified the actual high-value exports instead of relying on Pass616-Pass620 summaries. It also inspected the large `C:\AionTools\euroaion\game.dll.txt` dump; targeted network/port searches there surfaced address-substring false positives, not a receive path.

## Real Static Exports

- High-relevance exports found: `14`
- Key concrete files: `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, `pass8b_handler_table_from_ghidra.csv`, and Pass8C recursive flow outputs.
- Export scripts available: `EA_VM_TargetDumpJava.java` and `EA_VM_FlowDumpJava.java`.

## Trace Findings

- VM launch anchors are known: `0x11B566B4` and `0x11B56C63`.
- Dispatcher anchors are known: `0x11B562BD` bytecode fetch from `RSI`, `0x11B5630F` handler-table lookup via `R12 + RAX*8`, table base `0x11B54E6F`.
- Handler candidates `0x11B57796`, `0x11B5932F`, and `0x11B55DF6` exist in real exports/table material.
- No current export contains the native 7785 receive/world-handshake path, direction split, or concrete write into an S2C 8-byte rolling-key slot.

## Result

No S2C initial key candidate was found. No bounded validation was run. The next required artifact is exact and address-targeted; see `pass622_codex_exact_missing_exports.md`.
