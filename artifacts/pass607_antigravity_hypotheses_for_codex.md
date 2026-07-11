# Grounded Hypotheses for Codex - Pass607

This document provides a set of grounded hypotheses and test scenarios for Codex to implement and verify via Python scripts, without overwriting existing files.

## Hypothesis 1: Startup PCAP Handshake Key Derivation
- **Background**: In `startup_login_world_entry.pcapng` flow 59085, packet #9740 is a server S2C packet of length 11 bytes: `f27bc160cff2a4c0ebfdc3`.
- **Hypothesis**: This is the `SM_KEY` packet obfuscated with a custom static XOR mask.
- **Mask derivation**:
  Assuming the decrypted prefix is the standard `0B 00 F9 01 56 06 FE` (SM_KEY header):
  `mask = ciphertext ^ plaintext`
  `mask[0] = 0xF2 ^ 0x0B = 0xF9`
  `mask[1] = 0x7B ^ 0x00 = 0x7B`
  `mask[2] = 0xC1 ^ 0xF9 = 0x38`
  `mask[3] = 0x60 ^ 0x01 = 0x61`
  `mask[4] = 0xCF ^ 0x56 = 0x99`
  `mask[5] = 0xF2 ^ 0x06 = 0xF4`
  `mask[6] = 0xA4 ^ 0xFE = 0x5A`
  Custom Mask: `F9 7B 38 61 99 F4 5A`
- **Seed extraction**:
  The remaining 4 bytes of ciphertext are `c0 eb fd c3`.
  Applying the derived mask (bytes 0..3):
  `seed[0] = 0xC0 ^ 0xF9 = 0x39`
  `seed[1] = 0xEB ^ 0x7B = 0x90`
  `seed[2] = 0xFD ^ 0x38 = 0xC5`
  `seed[3] = 0xC3 ^ 0x61 = 0xA2`
  Derived server seed: `39 90 C5 A2`
- **Test session key**:
  `key8 = 39 90 C5 A2 A1 6C 54 87` (try both little/big endian order).
- **Test execution**: Codex should write a script to decrypt subsequent packets in the same flow using this key.

## Hypothesis 2: Login Session Key Coupling
- **Background**: `Program_AionOuterLayerProbe.txt` reports the Login Server session key as: `CE-E8-41-11-CE-7B-3E-FB-62-98-48-57-63-24-6A-19`.
- **Hypothesis**: The Game Server session key is derived from the Login Server key (e.g. by taking slices or applying a hash/XOR transformation).
- **Test execution**: Codex can test slices of the login key combined with the static tail `A1 6C 54 87`.

## Hypothesis 3: Opcode Complement Verification
- **Background**: Standard Aion C2S packets place the opcode at byte 2 and the bitwise NOT of the opcode at byte 3 of the decrypted header.
- **Hypothesis**: Successful decryption of a C2S packet will satisfy the relationship: `header[2] == ~header[3]`.
- **Test execution**: Codex can automate validation of decryption results by verifying this complement rule across the first 4 bytes of the plaintext blocks.
