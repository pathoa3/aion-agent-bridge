# Pass607 Antigravity Key Update Research

We researched and derived the likely public Aion packet cryptographic key update rules:

## 1. Standard Aion Packet Cryptography Architecture
- **Blowfish Key:** Static. The Blowfish key (`seed + tail`) is initialized once at connection startup and does not mutate.
- **XORpass Key (`ecx`):** Dynamic. The XORpass key starts with the seed and mutates sequentially over each C2S/S2C packet.
- **Direction-Specific State:** C2S and S2C streams maintain completely independent XORpass key states.

## 2. Key Update Rules

### Candidate Rule A: Standard Forward C2S XORpass (Decrypt-then-XOR)
1. Blowfish decrypts the payload first.
2. The XORpass loop runs forwards starting at offset 4:
   `decrypted_dword = ciphertext_dword ^ ecx`
   `ecx = (ecx + decrypted_dword) & 0xFFFFFFFF`
3. The final `ecx` at the end of the packet is used as the initial `ecx` for the next packet.

### Candidate Rule B: Backward S2C XORpass
1. Decrypts backward from the end of the packet.
2. The key is updated by subtraction:
   `ecx = (ecx - decrypted_dword) & 0xFFFFFFFF`

### Candidate Rule C: Ciphertext-based Forward XORpass
- The key updates using ciphertext dwords instead of decrypted dwords:
  `ecx = (ecx + ciphertext_dword) & 0xFFFFFFFF`
