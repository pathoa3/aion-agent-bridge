# Codex Report - Pass630 Path C FUN_11b581c1 Review

Reviewed only Path C exports: `FUN_11b581c1`, `FUN_11b56f43`, `FUN_11b5591a`, and `FUN_11b5625b`.

Result: Path C is a VM helper-dispatch setup, not a proven packet decode/keyroll path. `RSI` is structurally mapped as a decoded stack-frame value from `RSP+0xa0`; `[RBP+0]` is likely local zero after `RBP=RSP`; initial `BL/RBX` is still predecessor-provided. No receive/session context layout was found.

No bounded VM trace was run. Exact blocker: concrete caller stack value for `RSP+0xa0` is missing, and Path C has no packet/receive context linkage. Continue with Path B for the S2C receive/decode chain.
