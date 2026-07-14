# Pass660 Callsite SSA Correction

Scope: existing Pass659 local outputs only, transitions `0x1195DA7B -> 0x11B50330` and `0x11B50330 -> 0x11B56C63`.

Corrected STORE classification now uses STORE input 1 as the destination pointer and keeps STORE input 2 as the source-value slice. On the bounded transition functions, all deduped STORE destinations are stack-pointer based via `(register, 0x20, 8)`; no non-stack persistent context write was recovered.

The two call transitions resolve to thunk/tail-branch style edges, but the generated callsite argument metadata does not materialize RCX/RDX/R8/R9. Definitions were followed within the caller and one caller upward where available; they remain live-through rather than concretely defined in the current export.

No initializer or decoder was generated. Acceptance gate passed: False.

Exact next operation: rerun targeted exporter for 0x11B50330 with decompiler prototype/parameter storage and HighFunction local symbol map, emitting CALL op input varnodes and varnode defining ops for live-in RCX/RDX/R8/R9 at 0x11B50340/0x119BAEAB

No raw p-code/decompile text, packet bytes, keys, state, decoded blobs, captures, or hashes were committed.
