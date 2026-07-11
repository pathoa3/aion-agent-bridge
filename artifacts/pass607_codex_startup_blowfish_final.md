# Pass607 Codex Startup Blowfish Decoder Trials

## Boundary
Static/offline analysis only. No EuroAion, Destiny, Gamez, Aion4.9, or unknown client binary was run. No live process, debugger, memory dump, injection, anti-cheat bypass, or packet injection was used.

## Blowfish Provider
- provider used: pure_python
- module: `tools/pass607_codex_startup/blowfish_pure.py`
- self-test vectors: 3
- self-tests passed: yes
- artifacts: `pass607_codex_blowfish_selftest.md`, `pass607_codex_blowfish_selftest.csv`

## Packet 9741 SM_KEY
Packet 9741 remained confirmed as the matching SM_KEY packet on flow `192.168.178.127:59085 <-> 54.37.197.248:7785`.

- raw ciphertext: `F2 7B C1 60 CF F2 A4 C0 EB FD C3`
- mask: `F9 7B 38 61 99 F4 5A`
- decoded SM_KEY: `0B 00 F9 01 56 06 FE 39 90 C5 A2`
- candidate seed: `39 90 C5 A2`

## Startup Blowfish Trials
Tested candidate keys:

- `39 90 C5 A2 A1 6C 54 87`
- `A2 C5 90 39 A1 6C 54 87`
- `39 90 C5 A2 87 54 6C A1`
- `A2 C5 90 39 87 54 6C A1`

Trial coverage:

- startup packets after packet 9741 in the same 7785 flow: 51
- trial rows: 11,628
- order variants: Blowfish only, Blowfish then XORpass, XORpass then Blowfish, XORpass only
- skip variants: 0, 2, and 4 bytes for Blowfish-aligned regions
- validation: known plaintext markers, UTF-16LE/ASCII containment, printable UTF-16LE ratio, length sanity, opcode complement check, marker/say shape

Results:

- exact known plaintext recovered: no
- UTF-16LE/ASCII containment rows: 0
- matched messages: none
- decoder_success: false

## Pass574 Control
Pass574 was rechecked only as an implementation control. The startup key was not assumed to apply to Pass574.

- oracle rows: 15
- corrected parser used: `tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4`
- all raw lengths equal UTF-16LE byte length + 10: yes

## Decision
`blocked_startup_blowfish_no_plaintext_recovery`

The SM_KEY lead is real and useful as a session-key extraction fact for this startup capture, but the public Blowfish/XORpass family with the tested key, reversed seed, reversed tail, skip, and order variants did not recover known plaintext from the PCAP.

Next action: provide file-backed code/decompile/source evidence for the custom startup/game-channel transform or framing/key schedule variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.
