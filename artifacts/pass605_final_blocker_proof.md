# Pass605 Final Blocker Proof

## Answers
1. Public-control Aion4.x ASM/code reconstruction worked at the byte-pattern/pseudocode level from file-backed controls.
2. Public/reference signatures present in controls: exact staticKey, A1 6C 54 87 key tail, public false-key constants in Gamez, and rolling XOR mask motifs.
3. EuroAion/Destiny target aion.bin/game.dll are absent for exact staticKey, public false-key constants, SM_KEY/client/server key strings, and target executable co-occurrence candidates.
4. EuroAion/Destiny file-backed executable candidates found: 0.
5. Grounded decoder variants were tested against corrected Pass574 oracle frames.
6. They failed because no attempt recovered exact UTF-16LE oracle plaintext or containment.
7. Next unlock requires an unpacked/less-protected EuroAion binary, another comparable 4.6/4.7.5 client with visible packet crypto, custom transform source/decompile, or a legitimate file-backed decrypt/encrypt callsite.

## Decision
- decision = blocked_until_new_artifact
- decoder_success = false
- packet_sink_found = false
