# Codex Report - Pass607 Static Decoder Grind

## Questions Answered

### 1. Did controls reconstruct correctly?
Yes. The standard Aion 7.5 and 4.9 public emulator controls were fully reconstructed. The logic of `SM_KEY` initial handshake XOR masking, session key derivation, and Blowfish ECB + rolling XORpass were successfully documented in pseudocode.

### 2. Did target binaries contain any file-backed packet crypto candidate?
No. Both EuroAion `game.dll` and `aion.bin` contain zero plaintext matches for the Aion standard static key, false key constants, key tails, or custom packet processing motifs. This is because the `.text` sections are virtualized into Themida's `.aion1` and `.aion2` blocks.

### 3. Did any candidate produce clear text?
No. All tested public reference ciphers, nearby-version key variants, and XOR feedback algorithms failed to decrypt or decode the oracle frames from the Pass574 capture, yielding 0 matches.

### 4. Did passive PCAP evidence reveal key/state/reset?
No. While the PCAP highlights a strict `length + 10` invariant and packet-to-packet ciphertext divergence for identical plaintexts, the session key and rolling cipher parameters are negotiated dynamically at startup and obfuscated within the VM section.

### 5. What exact artifact is now required?
An unpacked or decrypted `game.dll` or `aion.bin` file, or a memory dump of the client process after initialization (which would expose the decrypted network handlers and session keys in plaintext memory).

### 6. Is another ordinary /say capture useful?
No. Additional ordinary captures will not bypass the virtualized binary problem.

### 7. Is startup/login/world-entry capture useful?
Only if we have a way to decrypt the initial handshake, which itself relies on the protected executable client routines.

### 8. What should be done next?
We recommend requesting the USER to provide either:
- An unpacked/less-protected build of Aion 4.6 `game.dll`.
- A dump of the initialized game process memory.
