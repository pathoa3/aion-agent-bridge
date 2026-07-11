# Pass607 Codex Startup Hypothesis Test

## Boundary
Static/offline PCAP and script analysis only. No client binary was run, no live process was attached/debugged, no memory dump was used, and no packet injection was performed.

## Packet 9740
- requested packet 9740 exists: yes
- requested packet 9740 matches Antigravity hex: no
- requested packet 9740 flow: 192.168.178.127:58145<->192.168.178.94:7680
- requested packet 9740 direction: unknown
- requested packet 9740 raw length: 0
- matching ciphertext found elsewhere: yes
- matching packet: 9741
- matching flow: 192.168.178.127:59085<->54.37.197.248:7785
- matching direction: S2C
- matching raw length: 11

## SM_KEY
- candidate mask: `F9 7B 38 61 99 F4 5A`
- candidate seed: `39 90 C5 A2`
- repeated 7-byte mask yields exact `0B 00 F9 01 56 06 FE 39 90 C5 A2` on matching ciphertext: yes

## Startup Key Trials
- trial rows: 1428
- marker matches: 0
- Blowfish provider unavailable: yes
- decoder_success remains false because no exact known plaintext was recovered from PCAP.

## Pass574 Recheck
- rows: 15
- all raw lengths equal UTF-16LE + 10: yes

## Decision
- decision: blocked_startup_key_not_plaintext_validated
- reason: The exact Antigravity ciphertext is not at parsed packet 9740; packet 9740 has no payload in a different flow. The same ciphertext is present at parsed packet 9741 on flow 59085, and the repeated 7-byte SM_KEY mask hypothesis is confirmed there. Startup key trials did not recover exact known plaintext. Pass574 oracle recheck length model ok=True. Blowfish-required rows were recorded as unavailable because no offline Blowfish provider is installed; XORpass-only rows found no markers.
