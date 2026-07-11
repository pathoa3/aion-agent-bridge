# Pass607 Codex Lobby Seed Blowfish Summary

- provider: cryptography
- self-test passed: yes
- lobby SM_KEY packet: 7522
- lobby packet direction: S2C
- lobby packet payload length: 11
- later world SM_KEY packet negative control: 9741, payload length 11
- target packets tested: 8745, 8844, 8974
- target packet directions: C2S, C2S, C2S
- key variants: 48
- trial rows: 4320
- exact UTF-16LE KXBOOT matches: 0
- matched messages: (none)
- best candidate key: lobby_seed_le+tail_ff / 735a1208ffffffff
- best candidate transform: decXORPass_then_Blowfish_ECB_xor_offset_4 offset=0
- packet_sink_found: false
- decoder_success is false unless exact known plaintext is recovered.

## Packet extraction
- packet 7522: direction=S2C flow=192.168.178.127:59085<->54.37.197.248:7785 len=11 hex=c16683f7d5265db93c68fe
- packet 8745: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=36 hex=bcdc2fd49ea450e8fd2134cafa1a0e502c656296a17d7094ff35ddf1ff4f266dce5ea9d1
- packet 8844: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=70 hex=f5214fbd0049b7b8b04a220786cc40917eb99e9d9cddbc21b31ef85735d9ebdd67cea90e68d849666129c7a51b328868db9b777c7f18ba27e9834d6263603b474acd429cf249
- packet 8974: direction=C2S flow=192.168.178.127:59085<->54.37.197.248:7785 len=58 hex=4dae0625faa681e8a27450b379aa26fe3e754d50ac8f98d7785263024a9c3cd2e05bfb81a37f1c9608b936d2d859bfb8466dcb892e54e0bfbc9e
- packet 9741: direction=S2C flow=192.168.178.127:59085<->54.37.197.248:7785 len=11 hex=f27bc160cff2a4c0ebfdc3
