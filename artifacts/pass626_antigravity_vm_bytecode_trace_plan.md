# pass626 VM Bytecode Trace Plan

This document outlines the static/offline plan to trace the VM bytecode execution around receive/decryption.

---

## Strategy: Bytecode Execution Emulation

Since S2C keys are managed via interpreted VM bytecode, we must emulate the decoding of bytecode from the `.aion1` section to see how keys are setup:

1. **Map Opcode Decryption**:
   - `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`
   - `BL = (BL - opcode) & 0xff`
2. **Track Virtual Register States**:
   - Trace virtual registers (corresponding to CPU registers like `R13`, `RAX` modified in handlers) across consecutive bytecode instructions.
3. **Locate Key Derivation Handler**:
   - Identify which handler (opcode) performs the arithmetic on key variables, and trace it in the sample byte streams.
4. **Identify PCAP Handshake Seed**:
   - Match the initial key setup bytecode operands against the seed bytes extracted from frame 4094 to verify the derivation.
