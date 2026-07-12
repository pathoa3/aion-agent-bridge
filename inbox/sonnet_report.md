# Sonnet Report: pass617 C2S Chat Extractor

## Result: SUCCESS – 11/11 KXSEQ messages found, exit code 0

---

## Tool location

```
tools/pass617_sonnet_c2s_chat_extractor/
  euroaion_c2s_chat_extractor.py   – core library
  run_extract_chat.py              – CLI runner + KXSEQ oracle
  README.md                        – usage and architecture
```

## Run statistics

| Metric | Value |
|---|---|
| C2S packets processed | 30 |
| CM_CHAT packets seen | 11 |
| Chat texts extracted | 11 |
| KXSEQ oracle | 11/11 PASS |
| First failure | none |

## What was built

A practical offline C2S chat extraction tool that:
1. Parses PCAPNG without external dependencies.
2. Detects the world TCP flow (port 7785) by anchor frame.
3. Rolls the C2S key sequentially across all 30 C2S packets.
4. Identifies CM_CHAT packets (decoded opcode 0x53).
5. Extracts UTF-16LE chat text stripped of trailing NULs.
6. Prints a clean frame/time/opcode/text timeline.
7. Validates against the 11-message KXSEQ oracle.
8. Writes local-only CSVs (not committed to git).

## Safety compliance

- Antigravity files: **not modified**.
- S2C stream: **not attempted**.
- No raw hex, byte blobs, or ciphertext committed to git.

## Next recommended step

Decode the S2C world stream (independent key schedule, not yet solved),
or apply this decoder to a new capture session to confirm generalizability.
