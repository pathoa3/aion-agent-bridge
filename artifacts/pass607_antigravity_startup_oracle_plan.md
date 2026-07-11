# Passive Startup Capture Oracle Plan - Pass607

This document evaluates the usefulness of passive startup captures and outlines a concrete plan for utilizing them to decode EuroAion network traffic.

## Answers to Key Questions

### 1. Could first server handshake reveal seed/state?
**Yes.** The very first S2C packet sent by the game server is `SM_KEY` (opcode `0xF9`). 
- In the Aion protocol, this packet is obfuscated with a version-specific static XOR mask (e.g. `0xCA 0x66...`) rather than a session-dependent rolling cipher or Blowfish block.
- Decrypting `SM_KEY` reveals the 4-byte random server seed.
- Combining this seed with the static key tail (`A1 6C 54 87`) produces the base session key `key8`.
- If the first handshake is captured, we obtain the session key. Without it, the session key is unknown, rendering all subsequent Blowfish blocks statically un-decryptable.

### 2. Could a KSTART_001 known plaintext immediately after world entry help?
**Yes.** 
- If a known plaintext is sent immediately after world entry, the connection key state has mutated only a minimal number of times.
- This bounds the state search space, allowing Codex to run validation checks against candidate session key derivations.
- Once the first early known plaintext is successfully recovered, the connection key state is synchronized, unlocking all subsequent chat frames.

### 3. What exact timing/log should user capture?
The user must perform the following capture sequence:
1. Start the network capture tool (Wireshark/tcpdump) **before** launching the game client.
2. Launch the game client, log in, select the character, and enter the world.
3. Immediately type a unique marker (e.g., `KSTART_001`) in the `/say` channel.
4. Wait 5 seconds, then type the rest of the oracle sequence.
5. Stop the capture.
6. Provide the exact local system timestamps when each message was sent, along with the client's `Chat.log`.

### 4. Is another ordinary /say capture useful?
**No.** An ordinary capture that begins after character login is useless because it misses the `SM_KEY` handshake. Without that initial packet, the dynamic session key cannot be recovered statically.

### 5. What would make the startup capture useful or useless?
- **Useful**: The capture includes the initial TCP connection handshake (`SYN`/`SYN-ACK`) on port 7785 and the first S2C data segment containing `SM_KEY`.
- **Useless**: The capture starts after the character has already entered the game world, meaning the handshake was missed.
