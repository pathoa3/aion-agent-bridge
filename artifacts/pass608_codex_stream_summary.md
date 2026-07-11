# Pass608 Codex KXSEQ Stream Hypotheses Summary

Git-safe summary only. Detailed differential and trial output stayed local-only under `C:\AionTools\aion_decoder_agent\outbox\pass608_kxseq_local\`.

## Previous Local Sequential Result
- total trial rows: 12320
- best score: 10.917
- best candidate label: `world_seed_tail_87546ca1`
- best update rule: `direct`
- best transform: `Blowfish_then_decXORPass offset=0`
- exact plaintext found: false
- any high UTF-16 printable structure: true

## Repeated Plaintext Differential
- frames tested: 4429, 4435
- same length: true
- ciphertexts identical: false
- simple period labels: (none)
- rolling-XOR strip offsets: (none)
- header/body split hint offsets: (none)

## Stream Trial Result
- target packets tested: true
- stream models tested: CFB-like, OFB-like, CTR frame, CTR C2S, CTR running-byte, LCG, XORpass counter, RC4-like, header/body separate
- state modes tested: direct_per_packet, sequential_c2s_15, bidirectional_state, no_update_control
- body/text offsets tested: 0, 2, 4, 6, 8, 10
- local-only trial rows: 19008
- exact UTF-16LE KXSEQ matches: 0
- matched message labels: (none)
- best candidate label: `world_seed_tail_a16c5487`
- best stream model: `B_Blowfish_OFB_like`
- best state mode: `bidirectional_state`
- best body offset: 6
- best score: 16.000

## Git Safety
- raw packet payload committed: false
- payload hash committed: false
- ciphertext XOR committed: false
- decrypted blob/prefix committed: false
