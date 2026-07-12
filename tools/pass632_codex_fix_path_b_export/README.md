# Pass632 Path B Export Fix

Pass631's targeted Ghidra export was invoked, but Ghidra headless reported that Python was unavailable because it was not started with PyGhidra. The output folder therefore contained only a log and no CSV/function exports.

This folder provides:

- `ghidra_export_path_b_xrefs.java`: Java Ghidra exporter equivalent for Path B xrefs/callers/import refs.
- `inspect_path_b_xrefs_fixed.py`: fixed Git-safe postprocessor. It refuses to replace useful known rows with an empty export unless a manifest/export explicitly proves no callers.

## Run Java Exporter

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass632_codex_fix_path_b_export" -postScript ghidra_export_path_b_xrefs.java "C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs"
```

## Fixed Postprocess

```cmd
python tools\pass632_codex_fix_path_b_export\inspect_path_b_xrefs_fixed.py --export-dir "C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs" --fallback-dir "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports" --repo-root "C:\AionTools\aion-agent-bridge"
```

Only commit Git-safe summaries, CSVs, scripts, and decision JSON.
