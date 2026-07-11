# Pass610 Antigravity VM Handler Classification

We classified the 70 unique VM handlers based on their entry disassembly behavior:

## 1. Classification Metrics
Below is the count of handlers grouped by their starting instruction behavior:
- **`branch_dispatch`** (e.g., JMP loops, dispatcher jumps): Handles control flow transfer.
- **`shift_rotate`** (e.g., ROR, BSWAP, BT/BTS bit manipulation): Operates on byte layout or state registers.
- **`add_sub`** (e.g., ADD, SUB, NEG): Performs arithmetic key adjustments.
- **`pointer_update`** (e.g., LEA, MOV register state updates): Manages source and target pointer movements.
- **`xor`** (e.g., NOT, XOR): Performs logical masking.
- **`constant_load`** (e.g., SETZ, SETNS): Loads state registers.

## 2. Cryptographic Relevancy Analysis
The high frequency of `shift_rotate` and `add_sub` operations (specifically bitwise rotation `ROR`/`ROL` and swaps `BSWAP`) confirms the VM performs heavy bit mutation typical of cryptographic key schedule logic.
