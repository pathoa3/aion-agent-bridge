# Phase 6 — Grounded Decoder Attempt Summary

This report documents all offline decryption attempts on the Pass574 PCAP captures.

## Test Summary
1. **Public Reference Blowfish ECB**:
   - Decrypted using `key8 = server_key + static_tail`.
   - Results in random bytes containing no visible ASCII/UTF-16 text.
2. **Rolling XORpass Loops**:
   - Tested multiple XOR structures with varying key states.
   - None successfully aligned or decrypted the C2S oracle message headers.
3. **Conclusion**:
   - The cipher logic employed by EuroAion differs from the standard public implementation.
   - Due to virtualization packaging of `game.dll`, the modified algorithms and keys cannot be reconstructed offline without dynamic execution traces or memory dumps, both of which are strictly forbidden under the safety guidelines.
