# Codex Report - Pass632 Path B Export Fix

Diagnosed the Pass631 empty result regression. Ghidra attempted to run `export_path_b_xrefs.py`, but headless was not started with PyGhidra, so Python was unavailable and no export CSVs were written.

The Pass631 postprocessor bug was that it treated the empty export folder as authoritative and overwrote the useful known Path B rows. The fixed postprocessor now restores from the Pass622 known-good export unless a new export explicitly proves no callers.

Created Java exporter: `tools/pass632_codex_fix_path_b_export/ghidra_export_path_b_xrefs.java`.

Fixed caller rows restored/found: `9`.
