# Pass621 Codex S2C Receive Handshake Trace Notes

## Static Export Inventory

Real static exports found: `48`. Primary usable exports are the Pass8B Ghidra target disassembly/p-code/flow files, handler table CSV, Pass8C recursive flow outputs, and the `EA_VM_TargetDumpJava.java` / `EA_VM_FlowDumpJava.java` scripts.

## Trace Result

- VM dispatcher evidence: confirmed. `0x11B562BD` is the VM bytecode fetch from `RSI`; `0x11B5630F` is the handler table lookup.
- Handler evidence: `0x11B57796`, `0x11B5932F`, and `0x11B55DF6` appear in handler/table/static export material, but none are connected to a receive handshake packet or S2C key-state write in the available exports.
- Receive/world-handshake path found: `false`.
- S2C 8-byte key write path found: `false`.

## Important Negative Finding

The actual Pass8B/Pass8C exports are VM launch/dispatcher/handler slices. They do not include the native 7785 receive path, server handshake parser, direction switch, or a concrete write into an S2C rolling-key slot. Memory writes visible in these exports are VM stack/context mechanics, not proven packet key state.

## Missing Export Needed

Generate a focused static p-code/disassembly/flow export around the native function(s) that call into the VM for world-server receive/decode handling, including call sites that initialize `RSI`, `RBP`, `R12`, and `R13` before dispatcher entry. The export needs to cover references to 7785 receive packet handling, SM_KEY/world handshake parsing, and writes to the suspected 8-byte send/recv key slots.

## Candidate Count

Candidate rows written: `53`.
