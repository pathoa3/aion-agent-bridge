# Pass623 Codex Keyslot Candidate Review

Scope was limited to the three requested local-only Ghidra export candidates: `P622-KS-002`, `P622-KS-007`, and `P622-KS-008`. I inspected only their exported `*.decomp.txt`, `*.pcode.txt`, and `*.disasm.txt` files under the Pass622 local export folder.

## Findings

| Candidate | Function | Store destination | Store source | Seed/key arithmetic source | Reachability | Verdict |
|---|---|---|---|---|---|---|
| P622-KS-002 | 0x11B559CD FUN_11b559cd | RSP stack slot after subtract 8 | RAX saved at entry | No | VM-adjacent graph depth 2; no direct receive/import or VM anchor hit | reject |
| P622-KS-007 | 0x11B564BE FUN_11b564be | RSP stack slot after subtract 8 | RDX saved at entry | No | VM-adjacent graph depth 3; no direct receive/import or VM anchor hit | reject |
| P622-KS-008 | 0x11B57075 FUN_11b57075 | RSP stack slots after subtract 8 | RBP first, then other register saves | No | VM path via 0x11B56C63 thunk; receive path not proven | reject |

## Conclusion

All three flagged writes are ordinary stack/register-save patterns from `PUSH` instructions, represented in p-code as `RSP -= 8` followed by a store to `[RSP]`. None writes to a packet/session/context base pointer, none has a visible stable offset suitable for an 8-byte S2C rolling-key slot, and none stores a value derived from seed/key arithmetic.

`P622-KS-008` remains useful only as a VM control-flow waypoint because it is reached through the `0x11B56C63` thunk. It is not a keyslot write candidate.

## Next Validation Step

Do not run S2C decoder validation from these candidates. Refine the keyslot scanner to reject stack-base writes (`RSP`/`register 0x20`) and continue with a focused caller trace of `0x11B56C63` / `FUN_11b50330` to identify the native receive/context setup that calls into the VM.
