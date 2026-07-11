# Codex Pass607 Lobby Sequential State Report

Decision: `blocked_lobby_seq_no_plaintext_recovery`

- 31 C2S data packets through first target processed: yes (30 strict intermediates + target 8745)
- sequential key-state simulation tested: yes
- exact KXBOOT plaintext recovered: no
- matched messages: (none)
- best update rule: F_no_update_negative_control
- best transform: previous_best_decXORPass_then_Blowfish_ECB_xor_offset_4 offset=4
- best candidate key: lobby_le_tail_ffffffff
- best score: 6.000
- raw payload committed: false

No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel key update, transform, or framing variant. Memory dumps are not recommended.

