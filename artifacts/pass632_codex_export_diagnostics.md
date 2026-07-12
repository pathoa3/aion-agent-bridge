# Pass632 Export Diagnostics

## Checks

1. Did `export_path_b_xrefs.py` run under Ghidra?

Yes, Ghidra attempted to execute it. The local log contains `Execute script: export_path_b_xrefs.py`.

2. Did it write files to `C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs`?

No usable export files were found. The folder contained `49` file(s), and the only observed required output was the log file.

3. Did the log contain exceptions?

Yes. The log reports: `Ghidra was not started with PyGhidra. Python is not available`.

4. Did `inspect_path_b_callers.py` read the right export directory?

It read the requested Pass631 export directory, but that directory had no CSV/function export files because the Python Ghidra script failed before writing them.

5. Why were the 9 known Path B rows removed?

Postprocessor bug: it treated an empty/broken export directory as authoritative and overwrote the useful previous rows with an empty CSV. The export did not explicitly prove no callers; it failed before producing data.

6. Fix applied

`inspect_path_b_xrefs_fixed.py` restores from the known-good Pass622 Path B rows when the new export is empty and lacks an explicit `explicit_no_callers` manifest. Empty exports can no longer clobber useful rows by accident.

7. Java exporter

Created `ghidra_export_path_b_xrefs.java` so headless Ghidra can export Path B xrefs without PyGhidra/Jython support.

## Current Fixed Result

- source used: `pass631_or_pass632_export`
- restored/found caller rows: `9`
- Python unavailable in Ghidra log: `true`
