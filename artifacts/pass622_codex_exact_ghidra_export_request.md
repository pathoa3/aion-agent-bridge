# Pass622 Exact Ghidra Export Request

Run the targeted exporter against the already-imported EuroAion `game.dll` Ghidra project.

## Script To Run

Primary:
`C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export\ghidra_export_s2c_receive_path.py`

Fallback Java script:
`C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export\ghidra_export_s2c_receive_path.java`

## Local Output Folder

`C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports\`

## Headless Command Template

```cmd
support\analyzeHeadless.bat "C:\Path\To\GhidraProject" "EuroAionGameDll" -process game.dll -noanalysis -scriptPath "C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export" -postScript ghidra_export_s2c_receive_path.py "C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
```

## Prioritize These APIs

`recv`, `WSARecv`, `recvfrom`, `send`, `WSASend`, `closesocket`, `connect`, `select`, `ioctlsocket`, `InternetReadFile`, `ReadFile`.

## Prioritize These VM Anchors

`0x11B562BD`, `0x11B5630F`, `0x11B5932F`, `0x11B57796`, `0x11B55DF6`, `0x11B54E6F`, `0x11B566B4`, `0x11B56C63`.

## Required Returned Local Files

- `export_manifest.json` or `export_manifest.txt`
- `import_refs.json` or `import_refs.csv`
- `candidate_functions.json` or `candidate_functions.csv`
- `call_edges.json` or `call_edges.csv`
- `write_hints.json` or `write_hints.csv`
- per-function `*.pcode.txt`, `*.disasm.txt`, and `*.decomp.txt` in the local-only output folder

## What Codex Will Do Next

Run:

```cmd
python C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export\postprocess_s2c_exports.py --export-dir C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports --repo-root C:\AionTools\aion-agent-bridge
```

Then inspect only Git-safe summaries for:

- receive wrappers that also reach VM dispatcher/caller code,
- 8-byte or adjacent-dword writes to packet/session context,
- seed/key arithmetic feeding a recv-direction key slot,
- concrete S2C initial key derivation rule before any bounded PCAP validation.

Do not commit local p-code/disassembly dumps unless separately reviewed and summarized.
