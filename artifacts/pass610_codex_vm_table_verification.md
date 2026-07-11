# Pass610 VM Table Verification

Static/offline text analysis only. No target binary was executed and no raw binary bytes are included.

## Findings
- `EA_VM_TargetDumpJava.java` present: true
- table constant `0x11B54E6F` present: true
- add constant `0x15F664FE` present: true
- exporter loop covers 256 opcodes: true
- handler formula in exporter: true
- generated handler table CSV present locally: false
- generated P-code text present locally: false

## Verification Status
The Java exporter verifies the claimed constants and contains a 256-iteration handler-table dumper using `handler = int64(entry) + 0x15F664FE`. However, the generated `pass8b_handler_table_from_ghidra.csv` is not present locally, so Codex could not independently verify all 256 resolved handler addresses, uniqueness, repetition, or compression from actual table entries.

## Known Reported Handler Groups
- `0x11B57796`: reported for opcodes 71, 113, 120, 157, 187, 231, 247.
- `0x11B5932F`: reported for opcodes 132, 160, 208, 235.
- Dispatcher lookup notes include opcode fetch at `0x11B562BD` and table lookup at `0x11B5630F`.
