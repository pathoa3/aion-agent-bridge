# Pass610 VM Handler Classification

Classification was limited by missing generated P-code/disassembly outputs. The available Java exporter lists dump ranges and Antigravity notes name two repeated handler groups, but it does not contain handler bodies or table entries.

## Current Classification Quality
- Dispatcher ranges: classified by exporter range names and report lines only.
- Handler groups `0x11B57796` and `0x11B5932F`: classified as unknown/branch-dispatch candidates from notes, not semantic proof.
- No byte-wise XOR, rolling add/sub, memory-store loop, packet buffer write, or table-indexed transform handler is proven from current local exports.

## Required Improvement
Regenerate or provide `pass8b_target_pcode.txt`, `pass8b_target_disassembly.txt`, `pass8b_target_flows.csv`, and `pass8b_handler_table_from_ghidra.csv`. Those text exports are sufficient for the next bounded parser without running or attaching to the game.
