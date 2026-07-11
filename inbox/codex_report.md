# Codex Pass607 Startup Blowfish Report

Decision: `blocked_startup_blowfish_no_plaintext_recovery`

- Blowfish provider used: `pure_python`
- Blowfish self-tests passed: yes
- packet 9741 SM_KEY stayed confirmed: yes
- candidate seed: `39 90 C5 A2`
- candidate mask: `F9 7B 38 61 99 F4 5A`
- startup packets tested after packet 9741: 51
- trial rows: 11,628
- KSTART_001 recovered: no
- any known plaintext recovered: no
- decoder_success: false
- Pass574 UTF-16LE + 10 recheck after Blowfish implementation: yes

No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom startup/game-channel transform or framing/key schedule variant. Memory dumps are not recommended.
