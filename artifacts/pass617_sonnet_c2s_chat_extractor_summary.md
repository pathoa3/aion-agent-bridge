# pass617 Sonnet C2S Chat Extractor – Summary

## Status: SUCCESS

Oracle validation: **11/11 KXSEQ messages found**, exit code 0.

---

## Run statistics

| Metric | Value |
|---|---|
| C2S packets processed | 30 |
| CM_CHAT packets seen | 11 |
| Chat texts extracted | 11 |
| KXSEQ oracle match | 11/11 |
| First failure frame | none |
| All KXSEQ found | yes |

---

## Chat timeline (KXSEQ frames only)

| Frame | Rel-Time | Opcode | Recovered Text |
|---|---|---|---|
| 4329 | 0.208s | CM_CHAT | `KXSEQ_001` |
| 4353 | 0.232s | CM_CHAT | `KXSEQ_002_A` |
| 4360 | 0.239s | CM_CHAT | `KXSEQ_003_AA` |
| 4389 | 0.268s | CM_CHAT | `KXSEQ_004_AAA` |
| 4399 | 0.278s | CM_CHAT | `KXSEQ_005_AAAA` |
| 4402 | 0.281s | CM_CHAT | `KXSEQ_006_AAAAAAAA` |
| 4412 | 0.291s | CM_CHAT | `KXSEQ_007_AAAAAAAAAAAAAAAA` |
| 4417 | 0.296s | CM_CHAT | `KXSEQ_008_0123456789` |
| 4422 | 0.301s | CM_CHAT | `KXSEQ_009_ABABABABABABABAB` |
| 4429 | 0.308s | CM_CHAT | `KXSEQ_010_REPEAT` |
| 4435 | 0.314s | CM_CHAT | `KXSEQ_010_REPEAT` |

All complement checks passed (✓).

---

## Deliverables

| File | Description |
|---|---|
| `tools/pass617_sonnet_c2s_chat_extractor/euroaion_c2s_chat_extractor.py` | Core extractor library |
| `tools/pass617_sonnet_c2s_chat_extractor/run_extract_chat.py` | CLI runner with timeline output and KXSEQ oracle |
| `tools/pass617_sonnet_c2s_chat_extractor/README.md` | Usage and architecture docs |
| `artifacts/pass617_sonnet_chat_validation.csv` | KXSEQ validation table (labels only) |
| `artifacts/pass617_sonnet_c2s_chat_extractor_summary.md` | This file |
| `artifacts/pass617_sonnet_c2s_chat_extractor_decision.json` | Machine-readable decision |
| `inbox/sonnet_report.md` | Report |

---

## Safety compliance

- Static/offline only – no EuroAion binary run or attached.
- No raw hex, byte blobs, or ciphertext committed.
- Antigravity files not modified.
- S2C not attempted.

---

## Future work

- S2C stream decoding (independent key schedule, not yet solved).
- Real PCAPNG timestamp extraction (currently uses frame-relative synthetic time).
- Multi-capture batch mode.
