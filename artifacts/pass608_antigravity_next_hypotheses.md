# Pass608 Antigravity Next Bounded Hypotheses

If Codex's run does not yield immediate plaintext, we propose the following next bounded hypotheses to test on the `startup_world_open_kxseq` capture:

## 1. Key Update & Sequencing Hypotheses

### Hypothesis 1: Lobby Seed vs. World Seed
There are two sequential SM_KEY handshakes in this capture:
- Lobby handshake at `Frame # 4094` (seed: `19 1A 76 23`).
- World handshake at `Frame # 4119` (seed: `2D 66 BD 65`).
We must test:
  1. Key state initialized by the world seed `2D 66 BD 65` at `Frame # 4119`, mutated by the 15 intermediate C2S packets.
  2. Key state initialized by the lobby seed `19 1A 76 23` at `Frame # 4094`, mutated by all intermediate C2S packets (including the ones between lobby and world).

### Hypothesis 2: Bidirectional Key Mutation
- Test if the running XORpass key state is updated by BOTH C2S and S2C packet payloads.
- Test if the key is updated by a simple TCP sequence/acknowledgement difference or packet counter.

## 2. Framing & Decryption Alignment Hypotheses

### Hypothesis 3: Offset & Padding Alignment
- **Offset 2/4/6/8 Treatment:** The packet header has length and opcode. Test Blowfish decryption starting at offsets `0, 2, 4, 6, 8` on the accumulated key state.
- **Length Field Alignment:** The length field is checked to determine if it is encrypted or clear. In this capture, the length is not padded to 8-byte block sizes (e.g. lengths are 28, 32, 34, 36, 38, 46, 62, 50, 62, 42). This suggests that if Blowfish is used, it operates on a stream mode (like CFB, OFB, CTR) or it is a pure stream cipher (like RC4/LCG), or the packet is padded in-memory but the lengths written on the wire are the unpadded ones.
