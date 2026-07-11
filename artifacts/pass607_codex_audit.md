# Pass607 Codex Audit

Audit of pre-existing Pass607 artifacts. This does not accept the old decision as final.

## wrong_version_context
- severity: medium
- evidence: Prior public-control text labels the control as Aion 7.5 while this branch is Aion 4.6/nearby public reference truthing.
- resolution: Treat as stale context label; do not use as EuroAion evidence.

## unsupported_section_name
- severity: medium
- evidence: Prior report mentions .aion2, but section inventory shown for target files lists .aion0/.aion1 only.
- resolution: Correct new report to .aion0/.aion1 only unless a file actually contains .aion2.

## empty_target_static_candidates
- severity: high
- evidence: pass607_target_static_candidates.csv contains only header/no rows.
- resolution: Run independent static scan and keep candidate_found=false if still empty.

## decoder_attempts_only_three_frames
- severity: high
- evidence: Prior attempts used frames 7166,7200,7250.
- resolution: New decoder attempt harness must test all 15 corrected oracle frames.

## conflicting_forbidden_next_action
- severity: critical
- evidence: decision has passive_startup_oracle_needed=true but next_action asks for a clean memory dump.
- resolution: Remove memory-dump path; use only file-backed or passive-capture next evidence.
