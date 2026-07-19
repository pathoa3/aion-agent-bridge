# Pass676 Evidence Index

- `clean_checkpoint_v2.py`, `checkpoint_schema_v2.json`: prepared v2 object-table implementation and schema.
- `test_clean_checkpoint_v2.py`, `test_results.txt`: v2 and regression validation.
- `checkpoint_validation.json`: sanitized source/target checkpoint validation and object invariant.
- `state_comparison.json`: exact deterministic equivalence at 200M.
- `changed_page_manifest.csv`: single changed non-executable page.
- `receive_pointer_delta_scan.csv`, `candidate_disassembly.txt`: negative bounded receive scan.
- `replay_validation.txt`, `pass676_decision.json`: concise proven results and claim limits.
- `prepared_patch_validation.json`, `SHA256SUMS.txt`: supplied archive and durable artifact identities.
- `checkpoint_0200000000_v2/`: local immutable checkpoint; intentionally excluded from Git.