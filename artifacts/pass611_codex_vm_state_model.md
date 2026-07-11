# Pass611 Codex VM State Model

Codex reconstructed the state model from existing text/CSV exports only. No target binary was run or attached.

## Dispatch

- Raw VM opcode byte is fetched from `[RSI]`.
- Opcode decode formula from Pass610: `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`.
- Rolling decode key update: `BL = (BL - opcode) & 0xff`.
- Handler lookup: `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE`.
- Pass610 artifacts report 70 unique handlers across 256 opcodes.

## Current Packet-Buffer Model

The most specific packet-related fields remain candidates, not proven Codex facts. Available notes identify `[RSI + 0x24]` as a candidate packet buffer pointer, `[RBX + 0x50]` as a candidate length variable, and `[RBX + 0x48]` as candidate rolling crypto/session state. The P609-012 edge does not prove writes to these fields.

## Missing for Decoder Derivation

A handler-derived decoder needs full p-code/disassembly/dataflow for the top transform handlers, including register/memory inputs and writes. First-instruction classifications are enough to prioritize handlers, but not enough to derive a valid packet transform without guessing.
