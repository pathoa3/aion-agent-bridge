# pass618 Sonnet S2C World Stream Probe – Summary

## Status: BLOCKER – S2C initial key unknown

S2C inventory was built and the cipher formula was confirmed consistent,
but the key space stays maximally ambiguous from static analysis alone.

---

## Run statistics

| Metric | Value |
|---|---|
| S2C packets indexed | 163 |
| Bulk packets (≥1000 B) | 135 |
| Small packets (<1000 B) | 28 |
| Anchor candidates tested | 243 |
| Low-opcode hits (single-frame) | 120 |
| Anchor confirmed | **no** |
| Paths after 8 rolling steps | >50,000 (capped) |
| S2C decoder success | **no** |
| C2S tools modified | no |
| Antigravity files modified | no |

---

## Key findings

### Checkpoint S2C key `4e99ca25a16c5487` is invalid
Tests on all early S2C frames (4116, 4119, 4122) yield:
- opcode = 0x7A (above valid range)
- complement check: FAIL

The checkpoint key was incorrect.

### Cipher formula is consistent with C2S
- Rolling from frame 4116 through 4122 and into bulk frames: **no dead end**.
- Same `STATIC_KEY XOR` stream cipher applies to S2C.
- Same opcode complement check (`byte0 == ~byte2`) applies.
- Same key roll formula (linear + VM) applies.
- The cipher is not broken; only the initial key is unknown.

### Path space explodes through bulk frames
- Frame 4116 start: 92 paths.
- Frame 4119: 6,440 paths.
- Frame 4122+: >50,000 paths (capped), stays capped indefinitely.
- Cause: 1460-byte bulk data segments accept virtually all k0 values via the VM formula
  (`delta = rol32(VA, shift) * A + B` has a solution for every delta in the VA space).

---

## Root cause

**Missing input: S2C initial key.**

The S2C initial key is session-derived from the world server handshake seed.
The handshake itself is encrypted. Without a plaintext oracle for any early
S2C packet, static PCAP analysis cannot recover the key.

---

## What would break the blocker

1. **Known-plaintext S2C packet** — any S2C frame whose plaintext is known
   (e.g., a fixed-format ping with deterministic content, or a server banner string).
2. **Server handshake seed** — if the session seed derivation can be traced through
   the `game.dll` VM handlers for S2C key setup.
3. **Second capture session** — if the same seed appears in a login-phase capture
   that can be correlated.

---

## Deliverables

| File | Description |
|---|---|
| `tools/pass618_sonnet_s2c_decoder/euroaion_s2c_probe.py` | Core probe library |
| `tools/pass618_sonnet_s2c_decoder/run_probe_s2c.py` | CLI runner |
| `tools/pass618_sonnet_s2c_decoder/README.md` | Findings documentation |
| `artifacts/pass618_sonnet_s2c_inventory_summary.csv` | Inventory (no hex) |
| `artifacts/pass618_sonnet_s2c_anchor_candidates.csv` | Candidate table |
| `artifacts/pass618_sonnet_s2c_decoder_summary.md` | This file |
| `artifacts/pass618_sonnet_s2c_decoder_decision.json` | Machine-readable decision |
| `inbox/sonnet_report.md` | Report |

---

## Safety compliance

- Static/offline only. No binary run, no live process.
- No raw hex, byte blobs, or ciphertext committed.
- C2S tools (pass616, pass617) not modified.
- Antigravity files not modified.
