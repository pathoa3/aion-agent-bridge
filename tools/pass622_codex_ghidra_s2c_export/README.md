# Pass622 Ghidra S2C Receive Export Workflow

This folder contains a targeted offline Ghidra export workflow for the missing S2C receive/world-handshake path.

It is designed to run against an already imported `game.dll` Ghidra project. It does not run the client, attach to a process, dump memory, inject code, or require packet material.

## Goal

Export the native receive path that sits before the VM dispatcher and may initialize the S2C 8-byte rolling key slot:

- receive/import wrappers: `recv`, `WSARecv`, `recvfrom`, `ReadFile`, `InternetReadFile`
- send/control references used for direction context: `send`, `WSASend`, `connect`, `select`, `ioctlsocket`, `closesocket`
- caller/callee graph around receive wrappers up to depth 3
- intersections with VM dispatcher/handler anchors
- disassembly, p-code, decompile text, xrefs, call graph edges
- memory-write hints for 8-byte writes and adjacent 4-byte writes that may be key slots

## Local-only Export Folder

`C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports\`

The export may contain disassembly and p-code. Keep it local-only unless summarized by `postprocess_s2c_exports.py`.

## Headless Command Template

Edit project paths for your local Ghidra project, then run:

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export" -postScript ghidra_export_s2c_receive_path.py "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
```

If Python scripting is unavailable in your Ghidra build, use the Java script instead:

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export" -postScript ghidra_export_s2c_receive_path.java "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
```

After exporting, run:

```cmd
python tools\pass622_codex_ghidra_s2c_export\postprocess_s2c_exports.py --export-dir "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports" --repo-root "C:\AionTools\aion-agent-bridge"
```

Then inspect:

- `artifacts/pass622_codex_s2c_receive_export_targets.csv`
- `artifacts/pass622_codex_s2c_keyslot_write_candidates.csv`
- `artifacts/pass622_codex_s2c_export_decision.json`
