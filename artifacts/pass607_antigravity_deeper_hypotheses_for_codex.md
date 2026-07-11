# Pass607 Antigravity Deeper Bounded Hypotheses

We prepared a detailed checklist of exact, bounded hypotheses for Codex to execute in the next sequential run.

## 1. Test Specifications Matrix

### Hypothesis 1: Decrypted Payload-Driven Update (Standard Aion)
- **Input Packet Range:** 7526 to 8745 (C2S only).
- **Key Start Value:** Lobby seed `73 5A 12 08`.
- **Update Rule:** `ecx = ecx + decrypted_first_dword`.
- **Decrypt Order:** Blowfish ECB -> decXORPass.
- **Validation Rule:** UTF-16LE text containment check for `KXBOOT` on packet 8745.
- **Stop Condition:** Exact match or 100% trials exhausted.

### Hypothesis 2: Ciphertext-Driven Update
- **Input Packet Range:** 7526 to 8745 (C2S only).
- **Key Start Value:** Lobby seed `73 5A 12 08`.
- **Update Rule:** `ecx = ecx + ciphertext_first_dword`.
- **Decrypt Order:** decXORPass -> Blowfish ECB.
- **Validation Rule:** UTF-16LE text containment check.
- **Stop Condition:** Exact match.

### Hypothesis 3: Packet Counter-Driven Update
- **Input Packet Range:** 7526 to 8745 (C2S only).
- **Key Start Value:** Lobby seed `73 5A 12 08`.
- **Update Rule:** `ecx = ecx + packet_index_relative_counter`.
- **Decrypt Order:** Blowfish ECB -> decXORPass.
- **Validation Rule:** UTF-16LE text containment check.
- **Stop Condition:** Exact match.

### Hypothesis 4: Full Stream Update (C2S + S2C)
- **Input Packet Range:** All packets (both C2S and S2C) between 7522 and 8745.
- **Key Start Value:** Lobby seed `73 5A 12 08`.
- **Update Rule:** Standard Aion forward/backward updates.
- **Decrypt Order:** Blowfish ECB -> decXORPass.
- **Validation Rule:** UTF-16LE text containment.
- **Stop Condition:** Exact match.

## 2. Decryption & Alignment Variants
Codex must test the following block offsets:
- **Offsets:** `0, 2, 4, 6, 8`.
- **Header Treatment:** Clear header (first 2 or 4 bytes untouched) vs. fully encrypted payload.
