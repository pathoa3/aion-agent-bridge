# Antigravity Parallel Evidence Audit Report - Pass609 Autonomous Longrun Checkpoint

## 1. Audit of Codex Pass609 State
- Checked latest outputs: Codex trials on sequential and stream hypotheses (CFB/OFB/CTR/RC4/XORpass, offsets 0-10, lobby/world seeds) are finished and have yielded no plaintext.
- No raw binary or packet hex has been committed.

## 2. Independent Source & Transform Hunt
We triaged public and local sources for EuroAion packet transform candidates:
- **`Ghidra_VM_Table`** (Local): Isolated the post-processed Ghidra dispatch table of 256 handlers at `0x11B54E6F` using formula `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE`.
- Other scanned public repositories (`NewCrypt.java` variants, proxy frameworks) are public duplicates or unrelated to EuroAion custom crypt.

## 3. Local Evidence Synthesis
- Evaluated the Ghidra headless P-code output of the virtualized Themida `.aion1` segment stubs (`pass8b_target_pcode.txt`).
- The launch path (`0x11B566B4`) and dispatcher loops consist of heavily obfuscated VM stubs that dynamically decode the byte stream in memory.
- **Major Finding:** Isolated the concrete VM handler candidate table (`0x11B54E6F`) and mapped major handler entrypoints (e.g. `0x11B57796`, `0x11B5932F`).

## 4. Rationale & Bounded Hypotheses
Standard packet cryptanalysis on offline PCAPs is exhausted. Progress requires reverse-engineering the byte translation inside the VM handlers, or locating source/decompile evidence of the custom EuroAion launcher/client modifications.
