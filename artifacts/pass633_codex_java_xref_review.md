# Pass633 Java Path B Xref Output Review

## Export Inventory

Reviewed `49` files in `C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs`.

The Java export produced usable CSVs and per-function exports. The stale Pass632 text saying "No usable export files were found" is no longer correct for the current state; it only described the earlier failed Python/PyGhidra export.

Required index files present:
- `path_b_functions.csv`: `14` rows
- `path_b_call_edges.csv`: `17` rows
- `path_b_xrefs.csv`: `15` rows
- `path_b_import_refs.csv`: `9` rows
- `path_b_manifest.json`: present

## Exported Files

The exact file inventory is in `artifacts/pass633_codex_exported_files.csv`. It includes the Java exporter log, the old failed Python log, four index files, one manifest, and per-function pcode/decompile/disassembly exports for the Java-selected function set.

## New Xref Findings

Strictly new compared to Pass622:
- `0x11B59832 FUN_11b59832` appears as a Java-exported function row.
- `0x11B59832 -> 0x11B568D5` appears as a branch/helper edge.

Those two rows are recorded in `artifacts/pass633_codex_new_xrefs.csv`.

Important distinction: the Java export also contains five `direct_caller` rows that were absent from the Pass632 9-row caller summary, but most were already present in the older Pass622 export set:
- `0x11B59392 FUN_11b59392` -> tail branch to `FUN_11b559cd`
- `0x11B5586B FUN_11b5586b` -> tail branch to `FUN_11b56696`
- `0x11B56F43 FUN_11b56f43` -> Path C helper dispatch to `FUN_11b5591a`
- `0x11B5863D FUN_11b5863d` -> Path A-style BSF/small-integer path to `FUN_11b56b2c`
- `0x11B56C63 thunk_FUN_11b57075` -> Path D/startup thunk

## Why `real_non_entry_caller_found` Stayed False

Two issues were separated:

1. Parser issue: `inspect_path_b_xrefs_fixed.py` filtered Java `path_b_functions.csv` rows using only the old known Path B address terms. That dropped the Java `direct_caller` rows from the Pass632 caller summary. I patched the parser so Java `path_b_functions.csv` rows are retained.

2. Evidence issue: the recovered direct callers are not receive/socket callers and do not supply the blocked Path B tuple. They are VM branch/thunk/helper paths, including already rejected Path A/C/D style feeders. `path_b_import_refs.csv` contains import symbols, but no caller function is linked to `recv` or `WSARecv`.

## Register Sources

No new source was found for:
- RDX context
- RSI bytecode base
- `[RBP+0]` PC offset
- initial/effective BL

No S2C initial key or derivation path was found.

## Next Export Request

Only if continuing static trace: export callers/wrappers around the import thunk addresses for `recv`, `WSARecv`, and any code xrefs into those thunk entries, then intersect those wrappers with the Path B graph. The current Java Path B target export itself does not show a recv-related caller.
