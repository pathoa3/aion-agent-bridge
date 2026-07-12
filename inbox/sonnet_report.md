# Sonnet Report: pass618 S2C World Stream Probe

## Result: BLOCKED – S2C initial key not recoverable from static PCAP alone

---

## What was done

1. **S2C inventory**: Parsed all 163 S2C packets in the world flow (port 7785).
   - 135 bulk (1460 B), 28 small (<200 B).
2. **Checkpoint key invalidated**: `4e99ca25a16c5487` gives op=0x7A, complement FAIL on all frames.
3. **Bounded anchor search**: 243 candidates tested via k0 brute sweep; 120 single-frame low-opcode hits, all ambiguous.
4. **Sequential rolling**: Path count starts at 92, expands to 6,440, then caps at >50,000 through 1460-byte bulk frames and stays there indefinitely.

## Cipher formula finding

The S2C cipher **is the same formula as C2S**:
- Same `STATIC_KEY` XOR rolling stream cipher.
- Same opcode complement check (`byte0 == ~byte2`).
- Same key roll (linear + VM formula).
- No dead end encountered — cipher formula is consistent.

The **only missing piece** is the S2C initial key.

## Root cause of blocker

1460-byte bulk frames accept all 256 k0 values via the VM key-roll formula
(`delta = rol32(VA, shift) * A + B` has a solution for every delta when VA
ranges over the .aion1 section). The path space is permanently maximal.

## What would break the blocker

1. A known-plaintext S2C oracle packet (fixed-format ping or banner string).
2. The server handshake seed derivation path traced through `game.dll` VM handlers.
3. A second capture with the same seed that can be correlated.

## Safety compliance

- C2S tools (pass616, pass617): not modified.
- Antigravity files: not modified.
- No binary run, no live process.
- No raw hex committed.
