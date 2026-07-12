#!/usr/bin/env python3
"""Create the Pass622 Git-safe export plan and decision when Ghidra is not run here."""

import csv
import json
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
ART = REPO / "artifacts"
REPORT = REPO / "inbox" / "codex_report.md"
OUT_DIR = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
SCRIPT_DIR = REPO / "tools" / "pass622_codex_ghidra_s2c_export"

TARGET_ROWS = [
    {
        "target_id": "P622-EXP-001",
        "function_or_address": "WS2_32.recv / WSARecv / recvfrom import callers",
        "source_reason": "Pass621 missing native receive caller path; start at concrete receive APIs and wrapper callers, not VM dispatcher summaries",
        "recv_related": "true",
        "vm_related": "false",
        "keyslot_write_related": "unknown",
        "confidence": "high",
        "next_export_or_trace": "Run ghidra_export_s2c_receive_path.py and walk callers/callees depth 3 until receive buffer ownership and packet context pointer are visible",
    },
    {
        "target_id": "P622-EXP-002",
        "function_or_address": "functions comparing/routing world port 7785 and login port 2106",
        "source_reason": "Need to distinguish world-server receive path from login/control paths and false positive address substrings",
        "recv_related": "true",
        "vm_related": "false",
        "keyslot_write_related": "unknown",
        "confidence": "high",
        "next_export_or_trace": "Export decompile/p-code around receive wrappers and any constants/callers that select 7785/world connection state",
    },
    {
        "target_id": "P622-EXP-003",
        "function_or_address": "VM launch/caller functions that initialize RSI/RBP/R12/R13 before 0x11B566B4 or 0x11B56C63",
        "source_reason": "Pass621 proves dispatcher internals but not native caller that sets VM context registers for receive/decode",
        "recv_related": "unknown",
        "vm_related": "true",
        "keyslot_write_related": "unknown",
        "confidence": "high",
        "next_export_or_trace": "Walk xrefs/callers to 0x11B566B4, 0x11B56C63, 0x11B562BD, 0x11B5630F, and 0x11B54E6F; export caller decompile and p-code",
    },
    {
        "target_id": "P622-EXP-004",
        "function_or_address": "candidate handlers 0x11B57796 / 0x11B5932F / 0x11B55DF6 plus native continuations",
        "source_reason": "Known VM handler/table addresses may participate after VM dispatch, but need caller/context mapping before key claims",
        "recv_related": "unknown",
        "vm_related": "true",
        "keyslot_write_related": "unknown",
        "confidence": "medium",
        "next_export_or_trace": "Export xrefs/dataflow and memory writes; classify VM stack writes separately from packet/session key slot writes",
    },
    {
        "target_id": "P622-EXP-005",
        "function_or_address": "context/session struct memory writes: 8-byte stores or adjacent 4-byte stores",
        "source_reason": "S2C key state is expected to be an 8-byte rolling key slot or two adjacent dword slots reachable from receive handshake setup",
        "recv_related": "unknown",
        "vm_related": "unknown",
        "keyslot_write_related": "true",
        "confidence": "high",
        "next_export_or_trace": "Use write_hints.json and local p-code to verify base pointer, offset, seed arithmetic, and direction-specific recv/send slot selection",
    },
]

KEY_ROWS = [
    {
        "candidate_id": "P622-KS-REQUEST-001",
        "function_or_address": "unknown until Ghidra export is run",
        "write_pattern": "8-byte write or two adjacent 4-byte writes to packet/session context",
        "evidence": "Pass621 found no concrete key-slot write in existing VM-only exports; this row defines the required evidence shape",
        "possible_role": "S2C rolling-key slot initialization if reachable from receive/world-handshake path",
        "confidence": "pending_export",
        "next_test": "Run exporter, inspect write_hints.json, and only validate S2C frames if seed/key derivation is concrete",
    }
]


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main():
    ART.mkdir(parents=True, exist_ok=True)
    write_csv(ART / "pass622_codex_s2c_receive_export_targets.csv",
              ["target_id", "function_or_address", "source_reason", "recv_related", "vm_related", "keyslot_write_related", "confidence", "next_export_or_trace"], TARGET_ROWS)
    write_csv(ART / "pass622_codex_s2c_keyslot_write_candidates.csv",
              ["candidate_id", "function_or_address", "write_pattern", "evidence", "possible_role", "confidence", "next_test"], KEY_ROWS)

    command = ('support\\analyzeHeadless.bat "C:\\Path\\To\\GhidraProject" "EuroAionGameDll" '
               '-process game.dll -noanalysis -scriptPath "{}" -postScript ghidra_export_s2c_receive_path.py "{}"'
               ).format(SCRIPT_DIR, OUT_DIR)
    plan = """# Pass622 Codex Ghidra S2C Receive Export Plan

## Existing Material Inspected

Pass621 artifacts were inspected. They confirm real Pass8B/Pass8C Ghidra exports and VM dispatcher/handler evidence, but they do not include the native receive/world-handshake caller path, packet/session context setup, or S2C 8-byte key-slot writes.

## Export Workflow Created

Created `tools/pass622_codex_ghidra_s2c_export/` with Jython and Java Ghidra scripts, a headless command template, and local postprocessors.

The exporter starts from receive/network imports, walks callers and callees to depth 3, intersects with known VM anchors, and writes local-only p-code, disassembly, decompile text, xrefs/call graph, and memory-write hints.

## Exact Command Template

```cmd
{}
```

## Local-only Output Folder

`{}`

## Git-safe Outputs

- `artifacts/pass622_codex_s2c_receive_export_targets.csv`
- `artifacts/pass622_codex_s2c_keyslot_write_candidates.csv`
- `artifacts/pass622_codex_exact_ghidra_export_request.md`
- `artifacts/pass622_codex_s2c_export_decision.json`

## Current Result

Ghidra/headless was not run by Codex in this pass. No S2C key is claimed. The useful next step is to run the exporter against the already-imported `game.dll` Ghidra project, then run `postprocess_s2c_exports.py` to produce candidate function/keyslot tables.
""".format(command, OUT_DIR)
    (ART / "pass622_codex_ghidra_export_plan.md").write_text(plan, encoding="utf-8")

    request = """# Pass622 Exact Ghidra Export Request

Run the targeted exporter against the already-imported EuroAion `game.dll` Ghidra project.

## Script To Run

Primary:
`C:\\AionTools\\aion-agent-bridge\\tools\\pass622_codex_ghidra_s2c_export\\ghidra_export_s2c_receive_path.py`

Fallback Java script:
`C:\\AionTools\\aion-agent-bridge\\tools\\pass622_codex_ghidra_s2c_export\\ghidra_export_s2c_receive_path.java`

## Local Output Folder

`C:\\AionTools\\aion_decoder_agent\\outbox\\pass622_ghidra_s2c_receive_exports\\`

## Headless Command Template

```cmd
{}
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
python C:\\AionTools\\aion-agent-bridge\\tools\\pass622_codex_ghidra_s2c_export\\postprocess_s2c_exports.py --export-dir C:\\AionTools\\aion_decoder_agent\\outbox\\pass622_ghidra_s2c_receive_exports --repo-root C:\\AionTools\\aion-agent-bridge
```

Then inspect only Git-safe summaries for:

- receive wrappers that also reach VM dispatcher/caller code,
- 8-byte or adjacent-dword writes to packet/session context,
- seed/key arithmetic feeding a recv-direction key slot,
- concrete S2C initial key derivation rule before any bounded PCAP validation.

Do not commit local p-code/disassembly dumps unless separately reviewed and summarized.
""".format(command)
    (ART / "pass622_codex_exact_ghidra_export_request.md").write_text(request, encoding="utf-8")

    decision = {
        "worker": "codex",
        "phase": "pass622_ghidra_s2c_receive_export_generator",
        "ghidra_export_scripts_created": True,
        "headless_command_created": True,
        "existing_static_exports_inspected": True,
        "ghidra_exports_generated_locally": False,
        "receive_export_targets_count": len(TARGET_ROWS),
        "keyslot_write_candidates_count": 0,
        "s2c_initial_key_found": False,
        "s2c_key_write_path_found": False,
        "recv_handshake_path_found": False,
        "exact_ghidra_export_request_written": True,
        "bounded_s2c_validation_run": False,
        "s2c_decoder_success": False,
        "c2s_tools_modified": False,
        "sonnet_files_modified": False,
        "antigravity_files_modified": False,
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Created targeted Ghidra export workflow for the missing native receive/world-handshake path. Existing Pass621 exports remain VM-only, so no S2C key or key write path is claimed until the local-only Ghidra export is run.",
        "next_action": "run_ghidra_export_s2c_receive_path_against_imported_game_dll_then_postprocess_local_exports"
    }
    (ART / "pass622_codex_s2c_export_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")

    report = """# Codex Report - Pass622 Ghidra S2C Receive Export Generator

Created targeted Ghidra export workflow under `tools/pass622_codex_ghidra_s2c_export/`.

Ghidra was not run in this Codex pass. Existing Pass621 artifacts were inspected and remain insufficient because they cover VM dispatcher/handler slices but not the native receive/world-handshake caller path or S2C key-slot writes.

Exact command template:

```cmd
{}
```

Local-only export folder:
`{}`

Git-safe result:
- receive export targets: `{}`
- concrete keyslot write candidates found before running Ghidra: `0`
- S2C key found: `false`

Next action: run the exporter against the already-imported `game.dll` Ghidra project, then run `postprocess_s2c_exports.py` and inspect candidate receive/VM/keyslot intersections.
""".format(command, OUT_DIR, len(TARGET_ROWS))
    REPORT.write_text(report, encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
