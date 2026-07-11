# Codex Pass607 Lobby Seed Blowfish Report

Decision: `blocked_lobby_seed_no_plaintext_recovery`

- Blowfish provider: `cryptography`
- Blowfish self-test passed: yes
- packet 7522 lobby SM_KEY source checked: yes
- lobby seed: `73 5A 12 08`
- later world seed `39 90 C5 A2` tested only as negative control: yes
- packets 8745/8844/8974 tested: yes
- exact KXBOOT plaintext recovered: no
- matched messages: (none)
- best candidate: lobby_seed_le+tail_ff / 735a1208ffffffff with decXORPass_then_Blowfish_ECB_xor_offset_4 offset=0

No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel transform, key schedule, or framing variant. Memory dumps are not recommended.
