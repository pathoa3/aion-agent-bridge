# Codex Report - Pass623 Keyslot Candidate Review

Reviewed only `P622-KS-002`, `P622-KS-007`, and `P622-KS-008` from the local Pass622 Ghidra export.

Result: no strong keyslot candidate. All three flagged stores are stack/register-save writes caused by `PUSH` patterns, not S2C rolling-key slot writes. `P622-KS-008` is the best control-flow waypoint because it is reachable through the `0x11B56C63` VM thunk, but it is still rejected as a keyslot write.

Next action: update the keyslot scan criteria to exclude `RSP` stack stores, then trace callers of `0x11B56C63` / `FUN_11b50330` for the native receive/context setup path.
