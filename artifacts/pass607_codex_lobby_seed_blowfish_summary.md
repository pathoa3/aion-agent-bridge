# Pass607 Codex Lobby Seed Blowfish Summary

- provider: pure_python
- Blowfish self-tests passed: yes
- lobby seed tested: `73 5A 12 08`
- negative/phase-boundary world seed: `39 90 C5 A2`
- lobby SM_KEY packet: 7522
- target packets tested: 8745, 8844, 8974
- target packet directions: C2S, C2S, C2S
- target packet lengths: 36, 70, 58
- key prefixes: 10
- tail variants: 4
- offsets: 0, 2, 4, 6, 8
- trial rows: 2400
- exact UTF-16LE known plaintext matches: 0
- matched messages: (none)
- best candidate key: formula_a9ea2bc5+tail_00000000 / a9ea2bc500000000
- best candidate transform: decXORPass_then_Blowfish offset=0
- best partial evidence: packet=8974 key=formula_a9ea2bc5+tail_00000000 transform=decXORPass_then_Blowfish offset=0 utf16_ratio=0.893 length_sane=yes hints= prefix_hex=4e00b390548beaef3bfb1dcf5d7a2115d3a6c76be878e1f4cfbe6cc122f2e123df683e395711ef1bf09a1b6a3fd95efe502cba88548dca2ae790
- decoder_success is false unless exact known plaintext is recovered.

## Packet Extraction
- packet 7522: direction=S2C flow=192.168.178.127:59085<->54.37.197.248:7785 len=11 hex=c16683f7d5265db93c68fe
- packet 8745: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=36 hex=bcdc2fd49ea450e8fd2134cafa1a0e502c656296a17d7094ff35ddf1ff4f266dce5ea9d1
- packet 8844: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=70 hex=f5214fbd0049b7b8b04a220786cc40917eb99e9d9cddbc21b31ef85735d9ebdd67cea90e68d849666129c7a51b328868db9b777c7f18ba27e9834d6263603b474acd429cf249
- packet 8974: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=58 hex=4dae0625faa681e8a27450b379aa26fe3e754d50ac8f98d7785263024a9c3cd2e05bfb81a37f1c9608b936d2d859bfb8466dcb892e54e0bfbc9e
- packet 9741: direction=S2C flow=192.168.178.127:59085<->54.37.197.248:7785 len=11 hex=f27bc160cff2a4c0ebfdc3
