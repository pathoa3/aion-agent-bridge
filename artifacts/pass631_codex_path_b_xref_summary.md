# Pass631 Codex Path B Xref Summary

Path B remains the only primary S2C receive/decode candidate:

`FUN_11b45846 -> FUN_11b566dd/0x11B566B4 -> FUN_11b56999 -> thunk_FUN_11b59337 -> FUN_11b59337 -> FUN_11b59832/FUN_11b59838 -> FUN_11b5625b`

## Existing Export Findings

- `0x1195D94A` is only a JMP into `0x11B52CE5`; it is not a meaningful caller.
- `0x11B52CE5` is only a thunk to `FUN_11b45846`.
- `FUN_11b45846` is a branch/thunk-like wrapper into `FUN_11b566dd` and embedded `0x11B566B4`.
- `FUN_11b56999` saves volatile registers and sets `RBP = RDI`, but this does not survive.
- `FUN_11b59337` overwrites `RBP = RDX`.
- `FUN_11b59838` prepares dispatcher scratch stack and tests `EDX` before `FUN_11b5625b`.

## Register State

The decisive missing value is `RDX`: Path B turns it into `RBP`, so dispatcher `[RBP+0]` depends on the unknown RDX context. Existing exports do not establish `RSI`, `RDX`, initial `RBX/BL`, or a recv/session context.

## Targeted Export Created

Created `tools/pass631_codex_path_b_xref_trace/` with a Ghidra exporter and offline inspector. The exporter targets xrefs/callers for Path B addresses and import callers around `recv`/`WSARecv` without broad scanning.

## VM Trace

No bounded Pass627 VM trace was run because the dispatcher tuple is not concrete.
