# Pass622 Codex Ghidra S2C Receive Export Plan

## Existing Material Inspected

Pass621 artifacts were inspected. They confirm real Pass8B/Pass8C Ghidra exports and VM dispatcher/handler evidence, but they do not include the native receive/world-handshake caller path, packet/session context setup, or S2C 8-byte key-slot writes.

## Export Workflow Created

Created `tools/pass622_codex_ghidra_s2c_export/` with Jython and Java Ghidra scripts, a headless command template, and local postprocessors.

The exporter starts from receive/network imports, walks callers and callees to depth 3, intersects with known VM anchors, and writes local-only p-code, disassembly, decompile text, xrefs/call graph, and memory-write hints.

## Exact Command Template

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export" -postScript ghidra_export_s2c_receive_path.py "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
```

## Local-only Output Folder

`C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports`

## Git-safe Outputs

- `artifacts/pass622_codex_s2c_receive_export_targets.csv`
- `artifacts/pass622_codex_s2c_keyslot_write_candidates.csv`
- `artifacts/pass622_codex_exact_ghidra_export_request.md`
- `artifacts/pass622_codex_s2c_export_decision.json`

## Current Result

Ghidra/headless was not run by Codex in this pass. No S2C key is claimed. The useful next step is to run the exporter against the already-imported `game.dll` Ghidra project, then run `postprocess_s2c_exports.py` to produce candidate function/keyslot tables.
