# Pass610 VM Execution Model

## Reconstructed From Current Text Exports
- VM table base: `0x11B54E6F` from `EA_VM_TargetDumpJava.java`.
- Handler formula: `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE` from exporter code.
- VM entry launch range starts at `0x11B566B4`.
- TLS launch range starts at `0x11B56C63`.
- Dispatcher1 range starts at `0x11B56200`.
- Antigravity notes state dispatcher1 uses `RSI` as instruction-stream pointer and decodes one opcode byte using `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`, then updates `BL = (BL - opcode) & 0xff` and `RSI += 1`.
- Exporter report lines name byte fetch at `0x11B562BD` and table lookup at `0x11B5630F mov rdx, [r12+rax*8]`.

## Not Yet Reconstructed
- Complete handler table entries and handler uniqueness/repetition from actual table values.
- Handler semantics for arithmetic, memory load/store, packet buffer writes, and stop/return behavior.
- VM stack/register model beyond RSI/RBX/R12/BL hints.
- Data memory region model and mapping from VM state to packet buffer/length/text-byte source.

## Execution Path Status
The dispatch-loop skeleton is plausible and partially reconstructed, but the execution path is not complete enough to emulate a packet-transform handler from current local files.
