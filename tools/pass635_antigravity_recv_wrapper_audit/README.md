# pass635 Recv Wrapper Audit

## Overview

Audits the pass634 recv/WSARecv import-wrapper export failure, fixes the BOM issue,
reruns the Ghidra export, and produces a definitive analysis of why the static path
from recv callers to Path B is inaccessible.

## Tools

| File | Purpose |
|---|---|
| `export_recv_import_wrappers.java` | Fixed Ghidra script (no BOM). Exports recv/WSARecv xrefs and wrapper functions. |
| `run_ghidra_export.py` | PowerShell-compatible runner for the Ghidra headless script. |
| `README.md` | This file. |

## Usage

```powershell
# Run Ghidra export (requires Ghidra project at C:\AionTools\euroaion\euroaion)
$GHIDRA = "C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC"
$SCRIPT  = "C:\AionTools\aion-agent-bridge\tools\pass635_antigravity_recv_wrapper_audit"
$OUTDIR  = "C:\AionTools\aion_decoder_agent\outbox\pass635_recv_wrappers"
& "$GHIDRA\support\analyzeHeadless.bat" C:\AionTools\euroaion euroaion `
  -process "game.dll" -noanalysis `
  -scriptPath $SCRIPT `
  -postScript "export_recv_import_wrappers.java" $OUTDIR
```

## Key Finding

All WS2_32 socket API references in Ghidra's xref database are **DATA type** (IAT slots only).
Zero code-level callers found. The caller code is in packed `.aion1` (VA > 0x114E2000),
inaccessible to Ghidra static analysis.

**Static path is exhausted. The S2C oracle route (known-plaintext) is the next step.**

## Pass634 Failure Root Cause

The Java script saved by pass634 had a UTF-8 BOM (`EF BB BF`). Ghidra's compiler
rejects this as an illegal character before any class compilation occurs. Fixed for pass635
by saving without BOM (verified: first bytes are `2F 2F 20` = `// `).
