# Phase 2 — Public Control Reconstruction

This document reconstructs the public Aion packet transform logic as implemented in standard game emulators (e.g. Aion4.9/Gamez controls).

## Public Aion Network Protocol Architecture

### 1. Connection Handshake & Key Exchange (SM_KEY)
Upon connection established (port 7777 / 7785), the server sends the first packet containing the session key seed.
- **Opcode**: `0xF9` (SM_KEY)
- **Encryption**: The first `SM_KEY` packet is XORed with a static version mask rather than Blowfish.
- **Mask (Aion 7.5)**: `0xCA, 0x66, 0x7A, 0xF6, 0x83, 0x20, 0xA3`
- **Decrypted structure**:
  - `[0..1]`: Packet length (`0x0B, 0x00` -> 11 bytes)
  - `[2]`: Opcode `0xF9`
  - `[3]`: Client state indicator `0x01`
  - `[4]`: Magic/Static server packet code `0x56`
  - `[5..6]`: Magic sub-code `0x06, 0xFE`
  - `[7..10]`: Random `server_key` bytes (e.g. `78 0C B2 3A`)
- **Key derivation**:
  `session_key = server_key (4 bytes) + A1 6C 54 87 (4 bytes)`

### 2. Subsequent Packet Encryption (Blowfish + XORpass)
All subsequent packets in both direction (C2S and S2C) are encrypted using a combination of Blowfish ECB block cipher and XORpass rolling key obfuscation.

#### Decrypt Flow
```python
def decrypt_packet(raw_data, session_key):
    # 1. Blowfish ECB decryption (8-byte blocks)
    decrypted_blocks = bytearray()
    for i in range(0, len(raw_data), 8):
        decrypted_blocks.extend(blowfish_ecb_decrypt(raw_data[i:i+8], session_key))
        
    # 2. XORpass decryption (4-byte rolling checksum loop)
    # The last 4 bytes of the packet represent the checksum/key
    count = len(decrypted_blocks) // 4
    pos = (count - 1) * 4
    ecx = read_u32_le(decrypted_blocks, pos)
    
    pos = pos - 1
    while pos >= 4:
        decrypted_blocks[pos] ^= (ecx >> 24) & 0xFF
        val = decrypted_blocks[pos] << 24
        
        pos -= 1
        decrypted_blocks[pos] ^= (ecx >> 16) & 0xFF
        val += decrypted_blocks[pos] << 16
        
        pos -= 1
        decrypted_blocks[pos] ^= (ecx >> 8) & 0xFF
        val += decrypted_blocks[pos] << 8
        
        pos -= 1
        decrypted_blocks[pos] ^= ecx & 0xFF
        val += decrypted_blocks[pos]
        
        ecx = (ecx - val) & 0xFFFFFFFF
        pos -= 1
        
    return decrypted_blocks
```
