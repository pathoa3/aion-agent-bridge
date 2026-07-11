# Pass607 Antigravity Next Bounded Hypotheses

If Codex's run against the lobby seed `73 5A 12 08` does not yield immediate plaintext, we propose a targeted set of next bounded hypotheses to test:

## 1. Key State & Sequence Mutation Hypotheses

### Hypothesis 1: Key State Mutation from Prior Packets
The lobby session `SM_KEY` occurred at `Pkt # 7522`, but the first chat message did not occur until `Pkt # 8745`. There are several intermediate C2S and S2C packets that may have mutated the Blowfish or XORpass key state.
- **Test Plan:**
  1. Count the number of C2S data packets between 7522 and 8745 (only C2S packets mutate the C2S key state).
  2. Implement a mock state mutator that runs the key update step for each intermediate packet before attempting decryption of the chat packet.

### Hypothesis 2: C2S and S2C Key Divergence
In standard Aion protocol, the Client-to-Server (C2S) and Server-to-Client (S2C) streams maintain completely independent cryptographic states.
- **Test Plan:** Verify that Codex's decryption uses a state initialized with the lobby seed but updated ONLY by C2S packet payloads, completely ignoring S2C packets.

### Hypothesis 3: Packet Counter / Sequence-Based XORpass
The XORpass key update might depend on the sequence number or a packet counter rather than (or in addition to) the decrypted bytes.
- **Test Plan:** Test LCG/XORpass key updates incorporating the packet counter (e.g., `count = packet_index - 7522`) or TCP sequence differences.

## 2. Framing & Decryption Alignment Hypotheses

### Hypothesis 4: Header Offset & Padding Alignment
The Blowfish cipher operates on 8-byte blocks. The packet layout may exclude parts of the header:
- **Offset 2 Alignment:** The first 2 bytes (length) are plain/XOR-only; the Blowfish cipher is applied starting at byte index 2 (padded to block size).
- **Offset 4 Alignment:** The first 4 bytes (length and opcode) are plain/XOR-only; the Blowfish cipher is applied starting at byte index 4.
- **Encrypted Header / Separated Text:** The opcode is encrypted using a different key or algorithm than the UTF-16 text payload.

### Hypothesis 5: XORpass Algorithm Constants
If EuroAion uses a modified XORpass LCG key update:
- Standard: `key = (key * 31 + val) & 0xFFFFFFFF` or similar.
- **Test Plan:** Test variations of the multiplier, addend, and bitwise constants (e.g., custom `keyXor`, `keyAdd`, `opXor`, `opAdd` parameters).
