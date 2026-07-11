# Pass610 Antigravity VM Execution Model

We reconstructed the virtual machine execution model based on P-code stubs and handler definitions:

## 1. Registers and Context Mapping
- **VM Instruction Pointer (VIP):** `RSI` register. Pointed to the encrypted byte stream.
- **Obfuscation Key (`BL`):** The lower byte of `RBX`. Mutates after each byte decoded.
- **Stack Frame Pointer:** `RBP`. Maps relative local scratch space via `[RBP + delta]`.
- **Context Block Pointer:** `RDI`. Context variables are mapped via `[RDI + offset]`, where `offset = offset - 0x140`.

## 2. Dispatcher Logic
1. **Fetch:** Fetch a raw byte from the instruction pointer:
   `raw = [RSI]`
2. **Decode:** Decrypt the raw byte using the rolling obfuscator key `BL` to recover the opcode:
   `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`
3. **Key Update:** Mutate `BL` using the newly decoded opcode:
   `BL = (BL - opcode) & 0xff`
4. **IP Advance:** Increment instruction pointer by 1:
   `RSI += 1`
5. **Resolve:** Lookup handler address using the base table `0x11B54E6F`:
   `handler_va = int64([0x11B54E6F + opcode * 8]) + 0x15F664FE`
6. **Jump:** Control jumps to `handler_va` natively.

## 3. Control Flow & Exit
Handlers execute native instructions to manipulate the VM registers/stack context, then jump back to one of the dispatcher entrypoints (`0x11B56200`, `0x11B57980`, or `0x11B58520`) to continue bytecode execution. Execution stops when a terminal handler (or native API bridge) returns control out of the VM loop.
