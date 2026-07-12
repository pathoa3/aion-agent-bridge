# pass617 – EuroAion C2S Chat Extractor

Offline, static-analysis-only C2S chat extractor for EuroAion (Aion 4.x) world captures.

Builds on the pass616 decoder library.  No live process, no injection.

---

## Files

| File | Purpose |
|---|---|
| `euroaion_c2s_chat_extractor.py` | Core library – decodes all C2S packets, extracts CM_CHAT text |
| `run_extract_chat.py` | CLI runner – prints timeline, validates KXSEQ oracle, writes local CSVs |
| `README.md` | This file |

Depends on: `../pass616_sonnet_c2s_decoder/euroaion_c2s_decoder.py`

---

## Quick start

```cmd
cd C:\AionTools\aion-agent-bridge\tools\pass617_sonnet_c2s_chat_extractor

REM Print chat timeline and validate KXSEQ oracle (exits 0 = all pass)
python run_extract_chat.py

REM Verbose key-roll trace
python run_extract_chat.py --verbose

REM Custom capture
python run_extract_chat.py path\to\capture.pcapng
```

---

## Output

### Console (clean, no hex)

```
Frame   Rel-Time  C  Opcode                  Chat Text
------  --------  -  ----------------------  --------------------
  4121     0.000s ✓  CM_VERSION_CHOOSE
  4144     0.023s ✓  CM_PING
  4275     0.154s ✓  CM_LEVEL_READY
  ...
  4329     0.208s ✓  CM_CHAT                   'KXSEQ_001'
  4353     0.232s ✓  CM_CHAT                   'KXSEQ_002_A'
  ...
```

### Local-only files (not committed to git)

Written to:
```
C:\AionTools\aion_decoder_agent\outbox\pass617_sonnet_c2s_chat_extractor_local\
  extracted_chat_local.csv    – frame, time, opcode, chat text
  keyroll_trace_local.csv     – per-frame opcode + key-roll type
  full_run.log                – complete run log
```

---

## Verified KXSEQ messages

| # | Chat text |
|---|---|
| 1 | `KXSEQ_001` |
| 2 | `KXSEQ_002_A` |
| 3 | `KXSEQ_003_AA` |
| 4 | `KXSEQ_004_AAA` |
| 5 | `KXSEQ_005_AAAA` |
| 6 | `KXSEQ_006_AAAAAAAA` |
| 7 | `KXSEQ_007_AAAAAAAAAAAAAAAA` |
| 8 | `KXSEQ_008_0123456789` |
| 9 | `KXSEQ_009_ABABABABABABABAB` |
| 10 | `KXSEQ_010_REPEAT` |
| 11 | `KXSEQ_010_REPEAT` |

---

## Architecture

```
run_extract_chat.py
  └─ euroaion_c2s_chat_extractor.py   (this tool)
       └─ ../pass616_sonnet_c2s_decoder/euroaion_c2s_decoder.py
            ├─ PCAPNG parser
            ├─ TCP flow extractor (port 7785)
            ├─ Stream cipher  (STATIC_KEY XOR rolling)
            ├─ Key-roll inference  (linear or VM)
            └─ Opcode decoder  (byte0 ^ 0xEE) − 0xAE
```

---

## Future work

- S2C stream decoding (independent key, not yet solved)
- Real timestamp extraction from PCAPNG EPB blocks
- Multi-session / multi-capture batch mode
