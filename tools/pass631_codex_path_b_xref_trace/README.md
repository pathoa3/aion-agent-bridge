# Pass631 Path B Xref Trace

Focused tooling for the only remaining primary S2C receive/decode candidate:

`FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838/FUN_11b59832 -> FUN_11b5625b`

Use this only against an already-imported Ghidra `game.dll` project. It does not run the client, attach to a process, dump memory, inject code, or use packet material.

## Local-only Export Folder

`C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs\`

## Headless Command Template

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass631_codex_path_b_xref_trace" -postScript export_path_b_xrefs.py "C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs"
```

## Postprocess Existing Or New Exports

```cmd
python tools\pass631_codex_path_b_xref_trace\inspect_path_b_callers.py --export-dir "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports" --repo-root "C:\AionTools\aion-agent-bridge"
```

If the Pass631 Ghidra export has been run, pass `--export-dir C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs` instead.
