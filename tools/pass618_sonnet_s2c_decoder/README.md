# pass618 – EuroAion S2C World Stream Probe

Offline, static-analysis-only S2C packet probe for EuroAion (Aion 4.x) world captures.

No live process, no injection.

---

## Files

| File | Purpose |
|---|---|
| `euroaion_s2c_probe.py` | Core library – inventory, anchor search, rolling attempt |
| `run_probe_s2c.py` | CLI runner – all three phases with local CSV output |
| `README.md` | This file |

Depends on: `../pass616_sonnet_c2s_decoder/euroaion_c2s_decoder.py`

---

## Quick start

```cmd
cd C:\AionTools\aion-agent-bridge\tools\pass618_sonnet_s2c_decoder
python run_probe_s2c.py
```

---

## Findings

### Phase 1 – S2C Packet Inventory

- **163 total** S2C packets in the world TCP flow (port 7785).
- **135 bulk** (≥1000 bytes) — world data load.
- **28 small** (<1000 bytes) — handshake, ping, and state packets.
- Small frames: 4094, 4101, 4103, 4105, 4108, 4111, 4116, 4119, 4122, 4277, and periodic 9-byte pings.

### Phase 2 – Anchor Candidate Search

- **Checkpoint S2C key `4e99ca25a16c5487`**: **invalid** — does not produce a valid opcode/complement on any small S2C frame.
- Brute k0 sweep on frame 4116 yields **120 low-opcode hits** across 243 candidates — all are statistically plausible but cannot be distinguished without a known plaintext.
- **No confirmed S2C anchor**.

### Phase 3 – Sequential Rolling

- Starting paths at frame 4116: **92** (from k0 sweep).
- After frame 4119: paths expand to **6,440**.
- After frame 4122: paths explode to **>50,000** and stay capped.
- **Reason**: 1460-byte bulk frames accept virtually all k0 values via the VM key-roll formula, so the path space never collapses.
- **No divergence** — the cipher formula is consistent, but the key space stays ambiguous.

---

## Root Cause / Blocker

**Missing input: the S2C initial key.**

The S2C initial key is derived from the server-side session seed sent in the world server handshake.
This seed is itself encrypted (sent in the early encrypted exchange at frames 4094–4122).
Without a known plaintext for any early S2C packet, static PCAP analysis alone cannot recover it.

**What would resolve this:**
1. A capture of the world server's unencrypted initial handshake (e.g., a network intercept at the server's NIC).
2. A known-plaintext S2C packet (e.g., a fixed-format server ping with known content).
3. The server-side seed derivation function (from game server source code or VM analysis of `game.dll`'s S2C key setup handler).

---

## Architecture

```
run_probe_s2c.py
  └─ euroaion_s2c_probe.py       (this tool)
       └─ ../pass616_sonnet_c2s_decoder/euroaion_c2s_decoder.py
```

---

## Local-only output

Written to:
```
C:\AionTools\aion_decoder_agent\outbox\pass618_sonnet_s2c_decoder_local\
  s2c_inventory_full.csv         – per-packet inventory
  s2c_candidate_trials_full.csv  – anchor candidate results
  s2c_keyroll_trace_local.csv    – rolling trace (paths per step)
```
