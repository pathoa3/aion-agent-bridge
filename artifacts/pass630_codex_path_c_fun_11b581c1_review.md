# Pass630 Codex Path C FUN_11b581c1 Review

Scope was limited to Path C exports: `FUN_11b581c1`, `FUN_11b56f43`, `FUN_11b5591a`, and dispatcher `FUN_11b5625b`.

## Path C Chain

Export graph confirms:

`FUN_11b581c1 -> FUN_11b56f43 -> FUN_11b5591a -> FUN_11b5625b`

## Register Findings

1. `FUN_11b581c1` does set `RSI` before the dispatcher chain. It loads a dword from its current stack frame at `RSP+0xa0`, subtracts `0x34453aee`, xors `0x718606d1`, and `FUN_11b56f43` increments `ESI` before passing onward.
2. `FUN_11b581c1` does not set `RBX/BL` for bounded dispatch. It reads/tests BL/BH and saves RBX, but initial `BL` remains predecessor-provided. In the dispatcher, `RBX` is later overwritten from `RSI`, making effective `BL` depend on the resolved `RSI` base.
3. `FUN_11b56f43` sets `RBP = RSP`. Since `FUN_11b581c1` set `RAX = 0` and then pushed `RAX` immediately before the path to `FUN_11b56f43`, `[RBP+0]` is likely the local qword zero PC offset. This is a local VM stack slot, not a context struct field.
4. Path C looks like VM internal helper/dispatcher setup. No receive/socket/session pointer access or packet buffer context is visible in these files.
5. Path C does not reveal a useful packet context struct layout for Path B. It reveals stack-frame based VM setup: stack slot `+0xa0`, local PC offset at `[RBP+0]`, and a scratch frame allocated by `FUN_11b5591a`.
6. No bounded VM trace was run. A trace would require a concrete value for the caller stack dword at `RSP+0xa0`, plus initial predecessor `BL/RBX` if needed.
7. Exact blocker: `decoded_RSI` is structurally known but not concrete because its stack source is unknown. Path C lacks packet/receive context linkage.

## Decision

Path C is not a packet decode/keyroll candidate with the current evidence. It is a useful VM helper-dispatch pattern, but the primary S2C receive/decode lead remains Path B.
