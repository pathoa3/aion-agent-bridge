# Pass607 Bounded Hypotheses for Codex

We constructed a targeted, bounded set of testable hypotheses for Codex to run against the PCAP chat payloads using the correct lobby seed.

## 1. Key Verification Parameters
- **Lobby Seed:** `73 5A 12 08` (derived from `Pkt # 7522`).
- **Target Chat Packets:** Packets 8745, 8844, and 8974.
- **Opcode Verification need:** Ops `0x002C` (/say) or `0x002D` (group) in little-endian.

## 2. Key Derivation & Layout Hypotheses

### Hypothesis 1: Seed Endian Variants
- **Prefix BE:** `73 5A 12 08`
- **Prefix LE:** `08 12 5A 73`
- **Prefix BE Formula A:** `((0x735A1208 - 0x3FF2CCCF) ^ 0xFAE492CD) & 0xFFFFFFFF` => `0xC52BEAA9` (BE: `C5 2B EA A9`, LE: `A9 EA 2B C5`)
- **Prefix LE Formula A:** `((0x08125A73 - 0x3FF2CCCF) ^ 0xFAE492CD) & 0xFFFFFFFF` => `0x309C8E23` (BE: `30 9C 8E 23`, LE: `23 8E 9C 30`)
- **Prefix BE Formula B:** `((0x735A1208 + 0x3FF2CCCF) ^ 0xFAE492CD) & 0xFFFFFFFF` => `0x4FF3F016` (BE: `4F F3 F0 16`, LE: `16 F0 F3 4F`)
- **Prefix BE Formula C:** `((0x735A1208 - 0x3FF2CCD7) ^ 0xCB92E4DF) & 0xFFFFFFFF` => `0xBD6E2F07` (BE: `BD 6E 2F 07`, LE: `07 2F 6E BD`)

### Hypothesis 2: Key Tail Variants
- Standard Aion Key Tail: `A1 6C 54 87`
- Reversed Tail: `87 54 6C A1`
- Null Tail: `00 00 00 00`
- Constant Tail: `FF FF FF FF`

## 3. Cryptographic Transform Hypotheses

### Hypothesis 3: Standard Aion Order (Blowfish ECB -> decXORPass)
1. Perform Blowfish ECB decryption on the ciphertext payload using candidate keys.
2. Run standard `decXORPass` in-place on the decrypted blocks.
3. Validate if the result has a valid header and opcode.

### Hypothesis 4: decXORPass -> Blowfish ECB
1. Run `decXORPass` in-place on the ciphertext payload.
2. Decrypt the result using Blowfish ECB.
3. Check for valid structure.

### Hypothesis 5: Blowfish Decryption Only
1. Decrypt payload using Blowfish ECB.
2. Check if the output has plaintext markers.

### Hypothesis 6: Header Offset Variants
- **Variant A (Entire packet):** Decrypt starting at offset 0 (using total packet length, padding if necessary).
- **Variant B (Payload only):** Decrypt starting at offset 2 (first 2 length bytes are left out, remaining padded to 8-byte block size).
- **Variant C (Offset 4):** Decrypt starting at offset 4 (first 4 bytes are length and opcode; remaining padded to 8-byte block size).

## 4. Verification Rules for Codex
- **Opcode Complement Rule:** For any decrypted block, check if `res[2] == ~res[3]` or `res[0] == ~res[2]`.
- **UTF-16LE Text Marker:** For C2S `/say` messages, the plaintext must contain `K X B O O T _ S A Y _` in UTF-16LE (Hex: `4b 00 58 00 42 00 4f 00 4f 00 54 00 5f 00 53 00 41 00 59 00 5f 00`).
