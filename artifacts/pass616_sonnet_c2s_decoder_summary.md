# pass616 Sonnet C2S Decoder – Summary

## Status: DECODER SUCCESS

Oracle validation: **11/11 KXSEQ messages recovered exactly** from
`startup_world_open_kxseq.pcapng`.  Exit code 0.

---

## Deliverables

| File | Description |
|---|---|
| `tools/pass616_sonnet_c2s_decoder/euroaion_c2s_decoder.py` | Core library – PCAP parser, stream cipher, key-roll inference |
| `tools/pass616_sonnet_c2s_decoder/run_decode_kxseq.py` | CLI runner – clean per-frame summary |
| `tools/pass616_sonnet_c2s_decoder/validate_kxseq_oracle.py` | Strict oracle – asserts all 11 labels; writes local-only CSVs |
| `tools/pass616_sonnet_c2s_decoder/README.md` | Algorithm documentation |
| `artifacts/pass616_sonnet_kxseq_validation.csv` | Validation result table (labels only, no hex/blobs) |
| `artifacts/pass616_sonnet_c2s_decoder_summary.md` | This file |
| `artifacts/pass616_sonnet_c2s_decoder_decision.json` | Machine-readable decision |
| `inbox/sonnet_report.md` | Report |

---

## KXSEQ Validation Results

| Frame | Label | Recovered Exact |
|---|---|---|
| 4329 | `KXSEQ_001` | yes |
| 4353 | `KXSEQ_002_A` | yes |
| 4360 | `KXSEQ_003_AA` | yes |
| 4389 | `KXSEQ_004_AAA` | yes |
| 4399 | `KXSEQ_005_AAAA` | yes |
| 4402 | `KXSEQ_006_AAAAAAAA` | yes |
| 4412 | `KXSEQ_007_AAAAAAAAAAAAAAAA` | yes |
| 4417 | `KXSEQ_008_0123456789` | yes |
| 4422 | `KXSEQ_009_ABABABABABABABAB` | yes |
| 4429 | `KXSEQ_010_REPEAT` | yes |
| 4435 | `KXSEQ_010_REPEAT` | yes |

No divergence frame.  All paths converged on identical chat text.

---

## Algorithm verified

- **Stream cipher**: left-to-right XOR with `STATIC_KEY` + rolling 8-byte key.
- **Key rolling (linear)**: `key += body_len` (64-bit LE) for simple packets.
- **Key rolling (VM)**: `key_lo32 += rol32(VA, shift) * A + B` where `VA` is a
  static address in the `.aion1` section of `game.dll`.
- **Opcode decode**: `(byte0 ^ 0xEE) − 0xAE mod 256`; complement byte2 == `~byte0`.
- **Length header**: 2-byte LE, XOR-masked; body follows unmasked.

---

## Safety compliance

- Static / offline analysis only.
- No EuroAion binary executed, attached, patched, or injected.
- No raw hex, byte blobs, or ciphertext committed.
- Antigravity files not modified.

---

## Future work

- S2C stream decoding (independent key schedule, not yet solved).
- Generalise anchor key derivation from the TCP handshake.
- Extend to additional capture sessions.
