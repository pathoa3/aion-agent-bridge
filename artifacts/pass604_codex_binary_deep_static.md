# Pass604 Codex Binary Deep Static

## Scope
- Independent Codex run; existing pass604 decisions were not trusted as final.
- Static/offline only over inbox/euroaion, inbox/captures metadata, and corrected decoder_work oracle artifacts.
- No live process, debugger, memory dump, injection, anti-cheat bypass, packet injection, or unknown binary execution.

## Method
- Parsed PE section tables directly from file bytes.
- Scanned file-backed bytes for exact public staticKey, SM_KEY/client/server key strings, false-key constants, key-tail constants, i&0x3f/i&0x7 motifs, and executable-section co-occurrence windows.
- Treated Aion4.9/Gamez positives only as public controls.
- Required target EuroAion/Destiny evidence to be file-backed crypto/key co-occurrence, not imports alone.

## Public Controls
- inbox\euroaion\Aion\Aion4.9\game.dll: exact_staticKey=1, false_key_hits=0, classification=public_reference_control
- inbox\euroaion\Aion\Gamez\game.dll: exact_staticKey=1, false_key_hits=4, classification=public_reference_control

## Target Files
- inbox\euroaion\Aion\Detiny\Aion.bin: staticKey=0, falseKeys=0, SM_KEY=0, keyTerms=0, execWindows=0 -> no_file_backed_packet_crypto_candidate
- inbox\euroaion\Aion\Detiny\Game.dll: staticKey=0, falseKeys=0, SM_KEY=0, keyTerms=0, execWindows=0 -> no_file_backed_packet_crypto_candidate
- inbox\euroaion\Aion\EuroAion\aion.bin: staticKey=0, falseKeys=0, SM_KEY=0, keyTerms=0, execWindows=0 -> no_file_backed_packet_crypto_candidate
- inbox\euroaion\Aion\EuroAion\game.dll: staticKey=0, falseKeys=0, SM_KEY=0, keyTerms=0, execWindows=0 -> no_file_backed_packet_crypto_candidate
- inbox\euroaion\Aion\EuroAion\version.dll: staticKey=0, falseKeys=0, SM_KEY=0, keyTerms=0, execWindows=2 -> no_file_backed_packet_crypto_candidate
- inbox\euroaion\Aion\EuroAion\libeay32.dll: OpenSSL/library crypto surface; not packet transform evidence -> irrelevant_library_crypto
- inbox\euroaion\Aion\EuroAion\ssleay32.dll: OpenSSL/library crypto surface; not packet transform evidence -> irrelevant_library_crypto

## Candidate Gate
- target candidates found: 0
- decoder tests generated/run: no
- decoder test reason: no target file-backed decrypt/encrypt/key candidate existed

## Decision
- decision = blocked_static_binary_exhausted
- reason = independent Codex scan found no new file-backed EuroAion/Destiny decrypt/encrypt/key candidate beyond public Aion4.9/Gamez controls
- decoder_success = false
- packet_sink_found = false

## Artifacts
- summary CSV: C:\AionTools\aion_decoder_agent\artifacts\pass604_codex_binary_deep_static.csv
- detail hits CSV: C:\AionTools\aion_decoder_agent\artifacts\pass604_codex_binary_deep_static_hits.csv
- decision JSON: C:\AionTools\aion_decoder_agent\artifacts\pass604_codex_decision.json
