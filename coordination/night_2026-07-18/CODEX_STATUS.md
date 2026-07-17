# Codex Status - Night 2026-07-18

Updated: 2026-07-18T00:55:00+02:00
Branch: worker/runtime-status
Owner: Codex

## Scope

- Continued only inside isolated H2 workspace: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture`.
- Baseline, production workers, `AION_LOCAL_WORKER_V22`, and `AION_LOCAL_WORKER_V22_2` were not touched.
- No sentinel injection, production promotion, network-mask analysis, broad fake-success API, RIP/branch/register forcing, or invalid-page mapping was used.

## Stage A Result

- Selected checkpoint: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture\results\checkpoints\latest.aionckpt`
- Checkpoint SHA-256: `3f16812e3be38889ca8a53216a685d438eacdaca2b65af56e34fc7955e068cdd`
- Note: no valid pre-fault checkpoint exists; selected checkpoint already contains 32 synthetic pages. This capture is the next allocation-boundary access, not the first historical access.
- Stage A evidence: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture\results_h2\h2_stage_a_stop_capture.json`
- Evidence SHA-256: `0c2e06e0e6e5d6a84b63178c86d140bdfa3af57ca8f6d919aada3bd87aa50eed`
- Run reason: `h2_capture_uc_error_fallback`
- Worker instructions: `725,423,268`
- API count in captured state: `1216` with last API marker `1217`
- Fault: `UC_MEM_READ_UNMAPPED`, size `4`, address `0x50003ac000`
- Instruction: `0x18022131b: 391e ; cmp dword ptr [rsi], ebx`
- Registers: `RSI=0x50003ac000`, `RBX=0xb9867f6f`, `RSP=0x7000ffdea0`, `RIP=0x18022131b`
- Allocation provenance: API 1217 `VirtualAlloc(size=0x360) -> 0x50003ab000`; rounded mapped page ends at `0x50003ac000`.
- Dynamic maps before access: `32`
- Page mapped after capture: `false`
- Executed history length: `512`
- API tail length: `100`
- GameMapped: `false`; target pages `0x10328de0`, `0x103294b0`, and `0x1120ae70` remain unmapped.

## Stage A Packaging

- One-command reproduction wrapper: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture\Run-H2StageA.ps1`
- Wrapper SHA-256: `687ab7a8fc7056af821039d5c28b07bf42446d33dd49623a72bbb124a8fec4b8`
- Harness SHA-256: `d6adcc30642932c20f758b66f43c430ccee437dc58e567c47b1712e1e12264f8`
- Focused tests: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture\tests_h2\test_h2_boundary.py`
- Focused tests SHA-256: `cad8d1d8ab29fd1240dec93c11d496b0b60908b4d436338daf4181bb6e92df7f`

## Validation

- `Run-H2StageA.ps1` native PowerShell parser validation: PASS.
- Python compile validation for H2 harness and tests: PASS.
- Focused H2 tests: PASS, 13 tests.
- Weak placeholder tests were replaced with assertions against the captured Stage A evidence and forbidden production-path strings.

## Exception Machinery Audit

- Audit artifact: `C:\AionTools\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\h2_allocation_boundary_stop_capture\results_h2\h2_exception_machinery_audit.json`
- Audit SHA-256: `bd36fbfd715b249365fdabc02f3aecc80f6e9f10f439f5b7b95615c1ecd1b886`
- Registered active VEH at capture: handle `0x5000198000`, handler `0x1801d857d`, `First=1`, guest/aion image region.
- Prior route observed: `RaiseException(0x40010006)` entered the existing software exception path and invoked handlers `[0x1801f9e46, 0x1801d857d]`; first handler returned `0xffffffff` and restored context.
- Stage B decision: NOT justified yet.
- Reason: current machinery only proves API-raised exception dispatch. It does not yet prove conversion of `UC_MEM_READ_UNMAPPED` into `STATUS_ACCESS_VIOLATION`, hardware-fault EXCEPTION_RECORD64 offsets, x64 CONTEXT layout, EXCEPTION_POINTERS ABI, stack shadow/alignment, or repeated unchanged-fault detection.

## Process State

- Process inspection after Stage A/audit found no H2/probe/corrected replay process still running; only the inspection PowerShell command matched the experiment paths.

## Exact Next Action

Add pure Stage B layout/ABI tests first: EXCEPTION_RECORD64 offsets/bytes, EXCEPTION_POINTERS addresses, full CONTEXT64 register round-trip, RCX handler argument, 32-byte shadow space and 16-byte alignment, first/last VEH ordering, continue-search chaining, continue-execution with modified context, unchanged repeated AV detection, and proof that `0x50003ac000` is never mapped. Only then run a short bounded AV-dispatch probe.
