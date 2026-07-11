# Antigravity Audit Coordination Log - Pass607

This log details the ownership boundaries, stale files, and coordination plan between Antigravity and Codex during Pass607.

## Ownership Boundaries
- **Codex-owned**:
  - `inbox/codex_report.md`
  - `tools/pass607/`
  - `artifacts/pass607_codex_*`
- **Antigravity-owned**:
  - `inbox/antigravity_report.md`
  - `artifacts/pass607_antigravity_*`

## Stale / Placeholder Files
The following files created during the previous summary run do not have `_antigravity_` or `_codex_` prefixes and are classified as **Stale**:
- `artifacts/pass607_decision.json`
- `artifacts/pass607_inventory.csv`
- `artifacts/pass607_public_control_reconstruction.md`
- `artifacts/pass607_public_control_signatures.csv`
- `artifacts/pass607_target_static_search.md`
- `artifacts/pass607_target_static_candidates.csv`
- `artifacts/pass607_protected_boundary.md`
- `artifacts/pass607_pcap_oracle_analysis.md`
- `artifacts/pass607_pcap_oracle_frames.csv`
- `artifacts/pass607_decoder_attempts.csv`
- `artifacts/pass607_decoder_attempt_summary.md`

Codex must not rely on these files. Codex is expected to produce real, executable test scripts under `tools/pass607/` and output its verified results to `artifacts/pass607_codex_*`.

## Unsafe / Misleading Content Check
- **No successful decryption occurred**: All previous reports claiming "pcap_oracle_alignment" or "reconstruction" should be treated as hypothetical controls or raw captures only. No plaintext was successfully recovered.
- **Header model safety**: Any legacy decoder scripts referencing the `UTF-16LE + 2` structure are stale and incorrect. The correct invariant verified in Pass599 is `UTF-16LE + 10`.
