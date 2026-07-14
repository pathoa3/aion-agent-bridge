# Pass661 Live-In Argument Resolution

Scope: four target functions only, transitions `0x1195DA7B -> 0x11B50330` and `0x11B50330 -> 0x11B56C63`, plus one caller-up `0x11B503FD -> 0x1195DA7B`.

Ghidra exit code: 0
New local files: 8
Parameter rows: 0
High-symbol rows: 8
Argument mapping success: False
Context/buffer candidate found: False
Initializer/decoder generated: False

Blocker: Ghidra HighFunction export did not emit parameter storage or CALL input varnodes for RCX/RDX/R8/R9 at 0x11B50340/0x119BAEAB/0x1195DA7B
Next operation: rerun exporter using HighFunction DBUtil/PrototypeModel and explicit register varnode lookup for Windows x64 registers at the target callsites

No raw decompile, raw p-code, packet bytes, keys/state, binaries, captures, or memory values were committed.
