# Phase 3 — Target Binary Deep Search

We performed a deep search across EuroAion and Destiny target executables (`game.dll`, `aion.bin`) for static keys, rolling XOR loops, and framing signatures.

## Findings Summary
1. **Static Keys and Constants**:
   - The public staticKey string (`nKO/WctQ...`) is completely absent from both `EuroAion/game.dll` and `Destiny/Game.dll`.
   - Standard key tails (`A1 6C 54 87`) and false key constants (`0xCD92E4DF`, `0x3FF2CCCF`) were not found in the file-backed bytes.
2. **Rolling XOR Motifs**:
   - Checked for instruction sequences performing `index & 0x3F` or `index & 0x07` shifts. No game-specific loops were identified.
   - Some generic compiler-generated masks exist in `version.dll` and `libeay32.dll`, but they relate to standard DLL redirects and OpenSSL structures, not packet payload ciphers.
3. **PE Section Obfuscation**:
   - Analysis of section tables shows that the `.text` executable code section has been virtualized/encrypted into Themida-protected sections (`.aion1` and `.aion2`).
   - Consequently, all network/crypto routines are concealed behind virtual machine boundaries, making recovery of transform constants statically impossible from file-backed bytes.
