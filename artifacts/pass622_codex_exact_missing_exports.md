# Pass622 Exact Missing Static Exports

## Required Tool/File

Create a new Ghidra Java exporter, for example `EA_VM_RecvHandshakeXrefsJava.java`, and run it against the same static `game.dll` sample used for Pass8B/Pass8C. Output should stay local first, then commit only sanitized summaries.

## Exact Export Targets

1. Xrefs/callers to VM launch and dispatcher anchors:
   - `0x11B566B4` entry launch start
   - `0x11B56C63` TLS/alternate launch start
   - `0x11B562BD` dispatcher byte fetch from `[RSI]`
   - `0x11B5630F` handler table lookup
   - `0x11B54E6F` handler table base

2. Xrefs/callers/dataflow around candidate handlers only if reached by a real caller/bytecode path:
   - `0x11B57796`
   - `0x11B5932F`
   - `0x11B55DF6`

3. Native networking/import caller slices:
   - imports or thunk xrefs for `WS2_32.recv`, `WSARecv`, `recvfrom`, `WSASend`, `send`, `connect`, `select`, `ioctlsocket`
   - p-code/disassembly for each caller that feeds data into packet decode/VM launch
   - any functions comparing or storing ports `7785` or `2106` as immediate values, but filter out address-substring false positives from `game.dll.txt`

4. Context/key-slot writes:
   - all `STORE`/`MOV [base+offset]` writes in caller slices where the base register is a packet/session/context pointer
   - 8-byte stores or two adjacent 4-byte stores near receive/decode setup
   - direction switch selecting send-key vs recv-key or separate C2S/S2C key slots

## Why This Should Reveal S2C Key Setup

Current Pass8B/Pass8C exports prove the VM dispatcher and handler table, but they begin inside VM launch/dispatcher code. They do not show who initializes `RSI`, `RBP`, `R12`, or `R13`, nor do they show the native receive/world-handshake parser. The S2C initial key must be assigned before S2C packet decode; therefore the missing bridge is either a native receive-path caller that initializes VM context from a server handshake packet, or a VM bytecode slice reached from that caller that writes an 8-byte receive key state.

## Validation After Export

1. Parse the new xref/flow export.
2. Identify a concrete write to an 8-byte S2C key slot or a derivation formula from server seed bytes.
3. If a concrete initial key/derivation rule emerges, run one bounded S2C validation only on Pass618 S2C frames, reporting frame number, header-valid boolean, opcode candidate, and first divergence frame.
4. Do not commit raw packet bytes, decrypted bytes, binary bytes, or hashes.
