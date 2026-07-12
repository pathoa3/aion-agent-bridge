# Antigravity Report: Sequential C2S Key Stream Decryption and Verification

## Executive Summary
This report documents the successful recovery of the exact UTF-16LE plaintext message `KXSEQ_001` from Frame 4329 in the world C2S packet stream of the EuroAion client session `startup_world_open_kxseq.pcapng`.

By tracing the C2S keys sequentially starting from the world connection establishment (Frame 4121), we mapped all sequential key rolling transitions. The transitions follow either a linear body length roll or the custom VM key update formula using parameters from the VM bytecode.

## Success Criteria Met
- **Primary success condition achieved**: Exact UTF-16LE plaintext `KXSEQ_001` recovered from Frame 4329 in the PCAP.
- **Safety**: Fully offline static analysis. Adhered to safety guidelines by not committing raw packet payload hex, hashes, decoded byte blobs, ciphertext XORs, or decrypted prefixes to this repository.

## Detailed Frame Decryption Flow
The C2S key progresses sequentially through the following frames:

1. **Frame 4121 (CM_VERSION_CHOOSE)**: Starts with initial C2S key. Decrypts to a valid packet header. Updates by VM formula using parameter from payload.
2. **Frame 4144 (CM_PING)**: Decrypts to a valid ping packet. Updates by linear roll (+5).
3. **Frame 4275 (CM_LEVEL_READY)**: Decrypts to a valid level ready packet. Updates by VM formula (VA `0x11B5932F`, shift 6).
4. **Frame 4277 (CM_CHAT_MAC)**: Decrypts to a valid chat MAC packet. Updates by VM formula (VA `0x11B4467D`, shift 9).
5. **Frame 4282 (CM_PING)**: Decrypts to a valid ping packet. Updates by VM formula (VA `0x115EBA29`, shift 31).
6. **Frame 4284 (CM_ENTER_WORLD_READY)**: Decrypts to a valid enter world ready packet. Updates by linear roll (+20).
7. **Frame 4287 (CM_PING)**: Decrypts to a valid ping packet. Updates by VM formula (VA `0x11B5932F`, shift 6).
8. **Frame 4292 (CM_PING)**: Decrypts to a valid ping packet. Updates by linear roll (+5).
9. **Frame 4308 (CM_PING)**: Decrypts to a valid ping packet. Updates by VM formula (VA `0x11B57AEC`, shift 30).
10. **Frame 4311 (CM_CHAT_MAC)**: Decrypts to a valid chat MAC packet. Updates by VM formula (VA `0x11B55CCB`, shift 23).
11. **Frame 4314 (CM_CHAT)**: Decrypts to a valid chat packet. Updates by VM formula (VA `0x11B580DC`, shift 31).
12. **Frame 4316 (CM_CHAT)**: Decrypts to a valid chat packet. Updates by VM formula (VA `0x11B55B5D`, shift 31).
13. **Frame 4320 (CM_CHAT)**: Decrypts to a valid chat packet. Updates by VM formula (VA `0x11B56F79`, shift 19).
14. **Frame 4322 (CM_PING)**: Decrypts to a valid ping packet. Updates by VM formula (VA `0x11B57363`, shift 30).
15. **Frame 4326 (CM_PING)**: Decrypts to a valid ping packet. Updates by VM formula (VA `0x11B55DF6`, shift 3).
16. **Frame 4329 (CM_CHAT)**: Decrypts to a valid chat packet containing the exact recovered plaintext `KXSEQ_001` in UTF-16LE.

This completes the verification of the C2S key schedule.
