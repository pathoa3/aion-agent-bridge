# pass616 – EuroAion Reusable C2S Decoder

Offline, static-analysis-only C2S packet decoder for EuroAion (Aion 4.x) world TCP connections.

No live process, no binary injection, no anti-cheat bypass.

---

## Files

| File | Purpose |
|---|---|
| `euroaion_c2s_decoder.py` | Core decoder library – PCAP parsing, stream cipher, key rolling |
| `run_decode_kxseq.py` | CLI runner – pretty-prints all decoded frames and KXSEQ match summary |
| `validate_kxseq_oracle.py` | Strict oracle validator – asserts exact plaintext recovery, writes local-only CSV logs |
| `README.md` | This file |

---

## Verified working capture

```
C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng
```

All 11 KXSEQ messages recovered with exact UTF-16LE plaintext match.

---

## Quick start

```cmd
cd C:\AionTools\aion-agent-bridge\tools\pass616_sonnet_c2s_decoder

REM Print per-frame decode summary
python run_decode_kxseq.py

REM Run strict oracle validation (exits 0 = all pass)
python validate_kxseq_oracle.py
```

---

## Algorithm

### Frame layout

```
[wire_len_lo] [wire_len_hi] [body bytes ...]
```

The 2-byte length header is masked; the body is decoded with a rolling stream cipher.

### Stream cipher

```
out[0]  = in[0] ^ key[0]
out[i]  = in[i] ^ STATIC_KEY[i & 63] ^ key[i & 7] ^ in[i-1]   (i ≥ 1)
```

`STATIC_KEY` = `nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9`

### Opcode encoding

```
opcode = (decoded_byte0 ^ 0xEE) − 0xAE   (mod 256)
complement check: decoded_byte2 == ~decoded_byte0 & 0xFF
```

### C2S key rolling (two verified modes)

**Linear roll** (simple packets, e.g. CM_PING after decode):

```
key += body_len   (64-bit little-endian)
```

**VM roll** (most packets):

```
delta    = rol32(VA, shift) * A + B   (mod 2^32)
key_lo32 += delta                     (mod 2^32; high 32 bits unchanged)
```

Where:
- `VA` is a static virtual address inside the `.aion1` section of `game.dll`
  (`0x11472000 .. 0x11B59A00`, ImageBase `0x10000000`)
- `A ∈ {0x0045BC57, 0x8045BC57}`
- `B ∈ {0x098E1FFC, 0x84C6D8A1, 0xD6C83B61, 0xAD90E57C, 0}`
- `shift ∈ 0..31`

The decoder infers `VA`, `A`, `B`, `shift` automatically from the constraint that the next packet's key must decode to a valid opcode (< 0x80).

### Anchor

Frame 4121 is the first world C2S packet after the handshake.  The initial key is recovered from prior session analysis and is embedded as `ANCHOR_KEY_HEX`.

---

## KXSEQ target frames

| Frame | Expected label |
|---|---|
| 4329 | `KXSEQ_001` |
| 4353 | `KXSEQ_002_A` |
| 4360 | `KXSEQ_003_AA` |
| 4389 | `KXSEQ_004_AAA` |
| 4399 | `KXSEQ_005_AAAA` |
| 4402 | `KXSEQ_006_AAAAAAAA` |
| 4412 | `KXSEQ_007_AAAAAAAAAAAAAAAA` |
| 4417 | `KXSEQ_008_0123456789` |
| 4422 | `KXSEQ_009_ABABABABABABABAB` |
| 4429 | `KXSEQ_010_REPEAT` |
| 4435 | `KXSEQ_010_REPEAT` |

---

## Local-only output (not committed to git)

`validate_kxseq_oracle.py` writes to:

```
C:\AionTools\aion_decoder_agent\outbox\pass616_sonnet_c2s_decoder_local\
  full_decoder_run.log
  decoded_messages_local.csv
  keyroll_trace_local.csv
```

These files contain decoded message text and key-roll trace and are **not** committed to git.

---

## Future work

- S2C stream decoding (independent key schedule, not yet solved)
- Generalise anchor key derivation from the handshake
- Support additional captures / sessions
