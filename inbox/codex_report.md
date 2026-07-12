# Codex Report - Pass631 Path B Xref Trace

Reviewed existing local Path B exports only and created targeted xref tooling.

Result: no real non-entry caller found in current exports. `0x1195D94A` and `0x11B52CE5` are entry/thunk jumps. Path B internals show `RBP` becomes `RDX`, so `[RBP+0]` depends on unknown RDX context. No recv-related caller is connected in current export tables.

No bounded VM trace was run. Next action is the targeted Ghidra export for Path B xrefs and recv/WSARecv wrapper linkage.
