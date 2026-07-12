# Codex Report - Pass622 Ghidra S2C Receive Export Generator

Created targeted Ghidra export workflow under `tools/pass622_codex_ghidra_s2c_export/`.

Ghidra was not run in this Codex pass. Existing Pass621 artifacts were inspected and remain insufficient because they cover VM dispatcher/handler slices but not the native receive/world-handshake caller path or S2C key-slot writes.

Exact command template:

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export" -postScript ghidra_export_s2c_receive_path.py "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
```

Local-only export folder:
`C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports`

Git-safe result:
- receive export targets: `5`
- concrete keyslot write candidates found before running Ghidra: `0`
- S2C key found: `false`

Next action: run the exporter against the already-imported `game.dll` Ghidra project, then run `postprocess_s2c_exports.py` and inspect candidate receive/VM/keyslot intersections.
