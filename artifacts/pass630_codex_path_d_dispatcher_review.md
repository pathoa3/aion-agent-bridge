# Pass630 Codex Path D Dispatcher Review

Scope was limited to Path D and already-exported direct context: `*11b57075*`, `*11b5625b*`, the `0x11B56C63` thunk, and `FUN_11b50330` caller context.

## Path D Summary

Path D exists as an embedded branch from `FUN_11b57075`:

- `0x11B577E8..0x11B577EA`: flag manipulation only.
- `0x11B577EB`: `TEST AL,BH`; affects flags only.
- `0x11B577ED`: aligns `RSP` with `AND RSP,-0x10`.
- `0x11B577F1`: jumps to dispatcher `FUN_11b5625b`.

This block does not assign `RSI`, `RBP`, `RBX/BL`, or a packet/session pointer before entering the dispatcher.

## Dispatcher State

`FUN_11b5625b` confirms the VM dispatcher mechanics:

- `R12` is set to handler table base `0x11B54E6F` before lookup.
- The byte fetch address is `RSI + qword [RBP+0]`.
- The opcode byte is transformed using the low byte of the effective `RSI` base, then rotated and used to index the handler table.
- The indirect target is table entry plus fixed adjustment plus `R13`.

## Answers

1. At `0x11B577F1`, `RSI`, `RBP`, and initial `RBX/BL` are incoming from an unexported predecessor. `RSP` has just been aligned. Incoming `R12` is not important because dispatcher overwrites it with `0x11B54E6F`.
2. `RSI` cannot be classified as a real bytecode base from this slice. The Path D block does not derive it from packet data or from aligned `RSP`.
3. `[RBP+0]` is structurally the dispatcher PC/bytecode offset, but the concrete value and source are not found.
4. Path D does not touch packet/receive context in the exported slice. It looks like VM control-flow/helper state unless a predecessor proves otherwise.
5. Path D cannot produce a bounded VM trace with the Pass627 runner from the current evidence.
6. Exact blocker: missing predecessor state that enters `0x11B577E8`, specifically concrete `RSI` base, concrete `RBP` context, and qword `[RBP+0]` PC offset.

## Verdict

Path D is a real dispatcher route, but not a packet decode candidate yet. It should not be used for S2C key derivation or bounded VM tracing until the predecessor that seeds `RSI` and `RBP` is exported.
