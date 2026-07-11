# Codex Pass607 Lobby Seed Blowfish Report

Decision: `blocked_lobby_seed_no_plaintext_recovery`

- Blowfish provider: `pure_python`
- Blowfish self-tests passed: yes
- seed `73 5A 12 08` tested: yes
- packets 8745, 8844, 8974 tested: yes
- exact KXBOOT plaintext recovered: no
- matched messages: (none)
- best candidate: formula_a9ea2bc5+tail_00000000 / a9ea2bc500000000 with decXORPass_then_Blowfish offset=0
- best partial evidence: packet=8974 key=formula_a9ea2bc5+tail_00000000 transform=decXORPass_then_Blowfish offset=0 utf16_ratio=0.893 length_sane=yes hints= prefix_hex=4e00b390548beaef3bfb1dcf5d7a2115d3a6c76be878e1f4cfbe6cc122f2e123df683e395711ef1bf09a1b6a3fd95efe502cba88548dca2ae790

No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel transform, key schedule, or framing variant. Memory dumps are not recommended.
