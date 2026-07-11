# Pass607 Codex Binary Static Decoder Audit

## Scope
Codex independently reran Pass607 as a static/offline analysis pass. The existing `pass607_decision.json` was used only as prior context, not as final authority.

Hard boundary observed: no client binary execution, no live process, no debugger, no memory dump, no injection, no anti-cheat bypass, and no packet injection.

## Ownership Fix
The prior bridge `inbox/codex_report.md` content was preserved as `artifacts/pass607_antigravity_summary_report.md`, and the inbox report was replaced before this run with a status note that real Codex Pass607 had not yet been run.

## Audit Of Existing Pass607
Codex found material issues in the prior artifacts:

- `wrong_version_context`: public-control text labeled the control as Aion 7.5 in an Aion 4.6/nearby branch.
- `unsupported_section_name`: prior report mentioned `.aion2` although the displayed target inventories showed `.aion0/.aion1`.
- `empty_target_static_candidates`: prior target static candidates CSV had no rows.
- `decoder_attempts_only_three_frames`: prior decoder attempts tested only frames 7166, 7200, and 7250.
- `conflicting_forbidden_next_action`: prior decision combined `passive_startup_oracle_needed=true` with a forbidden memory-dump next action.

Details are in `artifacts/pass607_codex_audit.md` and `artifacts/pass607_codex_audit.csv`.

## Real Codex Static Run
Scripts created under `tools/pass607/`:

- `inventory_files.py`
- `scan_static_signatures.py`
- `extract_pass574_oracle.py`
- `test_decoder_variants.py`
- supporting helpers: `common.py`, `audit_existing_pass607.py`

Generated artifacts:

- `artifacts/pass607_codex_inventory.csv`
- `artifacts/pass607_codex_static_signature_hits.csv`
- `artifacts/pass607_codex_static_signature_summary.md`
- `artifacts/pass607_codex_oracle_frames.csv`
- `artifacts/pass607_codex_oracle_analysis.md`
- `artifacts/pass607_codex_decoder_attempts.csv`
- `artifacts/pass607_codex_decoder_summary.md`

## Oracle Extraction
Corrected PCAP parsing was used:

```text
tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4
```

Results:

- oracle frames aligned: 15
- all raw C2S lengths equal UTF-16LE byte length + 10: yes
- frame 7166 raw TCP payload length: 22
- no decoder success claimed from extraction

## Static Signature Result
After correcting the classifier so `Aion4.9` and `Gamez` are treated as public controls, the scan result is:

- Aion4.9/Gamez public-control hits: public staticKey, key tail, false-key constants, rolling-mask motifs, WSA/send/recv strings
- EuroAion target primary files: only WSARecv/WSASend string/import-style hits
- Destiny comparable target files: only WSARecv/WSASend string/import-style hits
- EuroAion/Destiny target crypto-key candidate hits: 0
- packet sink found: false

Import/string presence alone was not treated as packet-sink proof.

## Decoder Test Result
Bounded decoder variants were tested against all 15 corrected Pass574 oracle frames.

- variants per frame: 81
- total attempts: 1215
- exact UTF-16LE oracle matches: 0
- UTF-16LE containment matches: 0
- decoded cleartext not written
- decoder_success.json not written

## Decision
`decision = blocked_static_binary_exhausted`

Reason: corrected oracle extraction is validated, public/control crypto is not new evidence, EuroAion/Destiny file-backed bytes expose no decrypt/encrypt/key candidate beyond import strings, and bounded decoder tests recover no exact oracle plaintext.

Valid next evidence must be file-backed or passive-only:

- unpacked or less-protected EuroAion `game.dll` / `aion.bin`
- source or decompile of the custom 7785 transform/key schedule
- comparable clean 4.6/4.7.5 client binary with visible packet crypto
- passive startup/login/world-entry capture only if it provides new file/oracle evidence; ordinary SAY capture alone is not useful without code-side evidence
