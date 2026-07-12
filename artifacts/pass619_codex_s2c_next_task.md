# Pass619 Codex S2C Next Task

## Purpose

Prepare the next Codex run for the S2C blocker without spending credit on repeated PCAP-only searches or broad crypto trials.

## Current State

- C2S is solved for the KXSEQ capture.
- Pass616 recovered all 11 KXSEQ C2S oracle messages exactly.
- Pass617 extracted all 11 C2S chat texts exactly.
- S2C is not solved.
- Pass618 confirms the S2C stream formula appears to match C2S: `STATIC_KEY` XOR rolling stream, opcode complement check, and the same linear/VM key roll family.
- Pass618 invalidated the checkpoint S2C key `4e99ca25a16c5487`.
- Pass618 static PCAP-only S2C search failed: anchor candidates remain ambiguous and path count explodes/caps through bulk frames.

## Blocker

The S2C initial key is unknown. Static PCAP-only analysis cannot recover it from the current capture because large S2C bulk frames leave too many viable key-roll paths.

## Exact Next Codex Task

Run a static/offline trace of S2C key setup and world-server handshake seed derivation in `game.dll` / VM handler artifacts.

Focus only on finding the source of the S2C initial key:

- Locate world-server handshake packet handling path.
- Trace server seed extraction/decryption into the S2C rolling key state.
- Identify whether S2C key setup reuses C2S constants/formula with a different seed or direction-specific initialization.
- Produce a file-backed candidate initial S2C key or a precise static blocker.

## Do Not Do

- Do not rerun broad PCAP brute force.
- Do not modify working C2S tools from Pass616/Pass617.
- Do not treat the C2S success as S2C success.
- Do not run, attach to, debug, inject into, or dump any client process.
- Do not commit raw packet data, decoded byte blobs, or binary bytes.

## Recommended First Files For Next Run

Read the Pass618 S2C decision/summary, Pass616/617 C2S summaries, and current `inbox/sonnet_report.md`, then inspect existing static VM/Ghidra artifacts for handshake/key setup references before generating any new tests.
