# Phase 5 — Passive PCAP Analysis

## Overview of Chosen Plaintext Capture (Pass574)
- **First Oracle Frame**: Wireshark frame 7166
- **Known Length Invariant**: `raw C2S packet size = UTF-16LE plaintext length + 10`
- This indicates the presence of a 10-byte encapsulation header (2 bytes size, 1 byte opcode, 1 byte direction, 1 byte checksum, etc.).

## Cryptographic Anomalies
1. **Identical Message Divergence**:
   - Compare frame 7577 (KX_REPEAT_AAAAAAAAAAAAAAAA) and frame 7603 (KX_REPEAT_AAAAAAAAAAAAAAAA). Both contain the identical UTF-16LE plaintext message.
   - However, their ciphertexts are completely distinct.
   - This proves that a rolling session key, a sequence-based initialization vector, or a feedback cipher state mutations is applied per-packet.
2. **Length + 10 Invariant**:
   - The size delta of 10 bytes remains perfectly constant regardless of message length (from 22 to 86 bytes).
   - This rules out any randomized padding scheme (like PKCS7 padding of variable sizes or block alignment padding).
   - A stream cipher or in-place XOR mechanism is therefore highly probable, but must be paired with rolling session state derivation.
