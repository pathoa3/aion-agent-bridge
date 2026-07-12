# Pass620 Codex S2C Context Layout Notes

## C2S Solved Context

Pass616/617 establish that C2S decoding works with the `STATIC_KEY` XOR rolling stream, opcode complement validation, and linear/VM key-roll family. The C2S tools are treated as read-only evidence in this pass.

## S2C Comparison

Pass618 indicates S2C likely uses the same cipher formula and key-roll family, but not the same initial key. Static PCAP-only analysis leaves many valid single-frame candidates and explodes through bulk frames, so the missing object is the S2C initial key or its handshake-derived seed.

## Context Split Assessment

A direction split is strongly implied at the state level: C2S and S2C share transform logic but require independent initial key state. This pass did not find a concrete file-backed struct offset for two adjacent 8-byte key slots. The next static trace should therefore target receive/world-handshake setup code rather than the already-solved stream transform.

## Practical Next Trace

Search native/VM static exports for call sites that route 7785 receive packets, decrypt or parse the server handshake/SM_KEY, and assign an 8-byte rolling key state used by S2C decode.
