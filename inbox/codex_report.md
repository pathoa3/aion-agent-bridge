# Codex Pass607 Report

Codex independently completed the Pass607 static/offline binary decoder audit.

Decision: `blocked_static_binary_exhausted`.

Key facts:

- corrected Pass574 oracle extraction confirmed 15 frames
- frame 7166 raw TCP payload length is 22
- all oracle C2S payloads match UTF-16LE byte length + 10
- public Aion4.9/Gamez crypto hits are controls only
- EuroAion/Destiny target files expose no file-backed decrypt/encrypt/key candidate beyond WSA/send/recv strings
- packet sink found: false
- decoder attempts: 1215 across all 15 oracle frames
- exact UTF-16LE oracle matches: 0
- UTF-16LE containment matches: 0
- decoder_success.json was not written

No forbidden methods were used. Next useful evidence must be file-backed: unpacked or less-protected EuroAion `game.dll`/`aion.bin`, source/decompile of the custom 7785 transform/key schedule, or a comparable clean 4.6/4.7.5 binary with visible packet crypto. Memory dumps, attach/debug, live process, injection, anti-cheat bypass, and packet injection are not valid next actions.
