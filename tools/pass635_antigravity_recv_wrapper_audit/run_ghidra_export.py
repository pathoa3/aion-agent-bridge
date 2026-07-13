"""
run_ghidra_export.py
====================
Runs the fixed export_recv_import_wrappers.java under Ghidra headless
to export recv/WSARecv wrapper xrefs into pass635_recv_wrappers.

PRECONDITIONS (verified before running):
  1. Ghidra is installed at C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC
  2. Ghidra project exists at C:\AionTools\euroaion\euroaion with game.dll imported
  3. The Java script is saved WITHOUT BOM (verified: first bytes 2F 2F 20 = "// ")
  4. Output dir: C:\AionTools\aion_decoder_agent\outbox\pass635_recv_wrappers

Root cause of pass634 failure:
  export_recv_import_wrappers.java was saved with a UTF-8 BOM (EF BB BF prefix).
  Ghidra's Java compiler treats the BOM as an illegal character ('\\ufeff'),
  causing a class-not-found error before any code runs.
  The fix is to save the file without BOM — done for pass635.

Usage:
  python run_ghidra_export.py

DO NOT run the game client, attach to processes, or dump memory.
This only drives Ghidra headless in read-only no-import mode.
"""

import subprocess, sys
from pathlib import Path

GHIDRA   = Path(r"C:\Users\patho\Downloads\ghidra_12.1.2_PUBLIC")
HEADLESS = GHIDRA / "support" / "analyzeHeadless.bat"
PROJECT  = Path(r"C:\AionTools\euroaion")
PROG     = "game.dll"
SCRIPT   = Path(r"C:\AionTools\aion-agent-bridge\tools\pass635_antigravity_recv_wrapper_audit")
OUTDIR   = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass635_recv_wrappers")
LOGFILE  = OUTDIR / "ghidra_pass635_recv_wrappers.log"

OUTDIR.mkdir(parents=True, exist_ok=True)

cmd = [
    str(HEADLESS),
    str(PROJECT), "euroaion",
    "-process", PROG,
    "-noanalysis",
    "-scriptPath", str(SCRIPT),
    "-postScript", "export_recv_import_wrappers.java", str(OUTDIR),
]

print("Command:", " ".join(cmd))
print(f"Log: {LOGFILE}")
print()

with open(LOGFILE, "w", encoding="utf-8") as log:
    result = subprocess.run(cmd, stdout=log, stderr=log, text=True,
                            encoding="utf-8", errors="replace")

print(f"Exit code: {result.returncode}")

# Read last 50 lines of log
lines = LOGFILE.read_text(encoding="utf-8", errors="replace").splitlines()
print("\nLast 30 log lines:")
for line in lines[-30:]:
    print(" ", line)

# Report what was produced
files = list(OUTDIR.iterdir())
print(f"\nFiles in output dir ({len(files)}):")
for f in sorted(files):
    print(f"  {f.name:60s}  {f.stat().st_size:>10,} bytes")
