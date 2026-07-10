# Next task for Codex  Pass604 deep static binary grind

Continue from Pass603. Do not repeat acquisition searches.

Goal:
Use all safe offline/static binary-analysis methods to recover enough EuroAion transform/key evidence to decode pass574_chosen_plaintext.pcapng into validated clear text.

Inputs:
- C:\AionTools\aion_decoder_agent\inbox\euroaion\
- C:\AionTools\aion_decoder_agent\inbox\captures\
- C:\AionTools\aion_decoder_agent\outbox\decoder_work\
- project memory / Pass590-Pass603 summaries

Allowed:
- static PE analysis
- section/entropy/packer mapping
- file-backed disassembly
- import xref scanning
- WSARecv/WSASend/send/recv wrapper tracing
- constant/motif search
- public 4.7.5/Gamez/Aion4.9 positive-control comparison
- Ghidra headless/rizin/capstone/pefile/yara/capa if available
- static symbolic/emulation of file-backed candidate functions
- decoder variant tests against the 15 corrected Pass574 oracle frames

Forbidden:
- live process
- debugger
- memory dump
- injection
- anti-cheat bypass
- packet injection
- running unknown binaries
- claiming packet sink from imports alone
- claiming success from noisy/partial strings

Required outputs:
- artifacts/pass604_binary_deep_static.md
- artifacts/pass604_binary_deep_static.csv
- artifacts/pass604_decision.json
- if candidates found:
  - artifacts/pass604_crypto_candidates.csv
  - artifacts/pass604_candidate_disasm/
  - C:\AionTools\aion_decoder_agent\outbox\decoder_work\pass604_decoder_attempt_summary.md

Success:
Only create:
- C:\AionTools\aion_decoder_agent\outbox\decoded_cleartext.txt
- C:\AionTools\aion_decoder_agent\outbox\decoder_success.json

if exact UTF-16LE oracle messages are recovered from the corrected Pass574 frames.

Stop condition:
If no file-backed decrypt/encrypt/key candidate is found after full static sweep:
decision = blocked_static_binary_exhausted
reason = protected/virtualized EuroAion code not recoverable from current file-backed bytes under allowed methods.
