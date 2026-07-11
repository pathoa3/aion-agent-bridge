# Codex Pass604 Deep Static Binary Analysis Report

Decision: `blocked_static_binary_exhausted`

- target candidates found: 0
- PE section check completed: yes
- code section .aion1 contains virtualized VM dispatch: yes
- static patterns (staticKey/public keys) present in EuroAion binaries: no
- Aion4.9 / Gamez public controls matched: yes
- decoder tests run against Pass574 oracle frames: yes (180 attempts, 0 matches)
- exact plaintext recovered: no
- decoder_success: false
- packet_sink_found: false

Reason:
The protected/virtualized EuroAion code is not recoverable from current file-backed bytes under allowed offline/static methods.
