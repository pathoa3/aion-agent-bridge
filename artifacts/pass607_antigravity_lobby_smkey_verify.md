# Pass607 Antigravity Lobby SM_KEY Verification

We verified the cryptographic derivation of the lobby session seed from the first handshake packet:

## 1. Handshake Packet Fact-Sheet
- **Packet Identifier:** `Pkt # 7522` in `startup_login_world_entry.pcapng`.
- **Timestamp:** `2026-07-08 17:01:52.960992` local time.
- **Direction:** S2C (`54.37.197.248:7785 -> 192.168.178.127:59085`).
- **Raw Ciphertext Payload (11 bytes):** `c1 66 83 f7 d5 26 5d b9 3c 68 fe`

## 2. Decryption & Mask Analysis
- **Mask Used:** Standard `Aion75Mask` (`CA 66 7A F6 83 20 A3`).
- **Header Decryption:**
  - `0xC1 ^ 0xCA = 0x0B`
  - `0x66 ^ 0x66 = 0x00`
  - `0x83 ^ 0x7A = 0xF9`
  - `0xF7 ^ 0xF6 = 0x01`
  - `0xD5 ^ 0x83 = 0x56`
  - `0x26 ^ 0x20 = 0x06`
  - `0x5D ^ 0xA3 = 0xFE`
  This yields `0B 00 F9 01 56 06 FE`, which is the standard `SM_KEY` protocol header (length 11, opcode `0x01F9`, type `0x56`, complement checks pass).
- **Seed Extraction:**
  Applying the repeated mask elements at indices 7, 8, 9, and 10:
  - `0xB9 ^ 0xCA = 0x73`
  - `0x3C ^ 0x66 = 0x5A`
  - `0x68 ^ 0x7A = 0x12`
  - `0xFE ^ 0xF6 = 0x08`
  This yields the seed **`73 5A 12 08`**.

## 3. Ambiguity Status
- **Is the mask standard Aion mask or custom?** It is standard.
- **Is seed extraction unambiguous?** Yes, the math is completely unique and unambiguous.
