# Pass620 Codex S2C Key Setup Static Trace

## Result

S2C initial key found: **no**.

This pass performed a narrow static/offline trace over the requested summaries, reports, Pass616/617/618 tool text, `EA_VM_TargetDumpJava.java`, and existing safe VM/static export summaries. It did not rerun C2S work, did not run broad PCAP brute force, and did not modify working C2S tools.

## Best Candidate

- Candidate: `CTX-002`
- Role: S2C initial key is session-derived from encrypted world-server handshake seed
- Confidence: medium
- Next test: static trace handshake seed extraction/assignment into recv/S2C key slot

## Findings

- C2S/S2C context split: **implied but not structurally located**. The solved C2S path and failed S2C probe indicate shared transform logic with independent initial key state.
- Handshake seed derivation path: **not found** as a concrete assignment/write path. Pass618 states this is the likely source, but the available text artifacts do not expose the native/VM write into the S2C key slot.
- Static search hits written: `697` Git-safe rows.
- Candidate rows written: `24`.
- Bounded S2C validation: **not run**, because no concrete candidate initial key or derivation rule was found.

## Blocker

The remaining blocker is a missing file-backed trace from the world/server handshake receive path to the S2C rolling key initialization field. PCAP-only search is exhausted for this purpose; the next useful work is targeted static tracing of receive-path key setup.

## Next Action

Trace native/VM static exports for the 7785 receive/world-handshake path until a concrete assignment to an S2C 8-byte rolling key slot is found, or generate a more focused static export around recv/decode handshake call sites.
