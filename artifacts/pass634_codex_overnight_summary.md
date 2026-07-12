# Pass634 Overnight S2C Static Solve

## Terminal Outcome

Terminal condition: `hard_blocker`.

I exhausted the currently available safe static/exported evidence around Path B without running the client, attaching to a process, dumping memory, or using packet payload material. No S2C initial key, key derivation path, or bounded trace tuple was found.

## Phase Results

### Phase 1 - Import Wrapper / Socket Caller Trace

Created `export_recv_import_wrappers.java` for a future targeted Ghidra run. Using current exports, `pass634_codex_exported_recv_wrappers.csv` contains `20` import/thunk rows. All currently visible recv/WSARecv/send-family entries have blank caller function fields, so no recv-related caller reaches Path B in the existing export corpus.

`recv_related_caller_found = false`.

### Phase 2 - Tail-Call / Indirect Branch Discovery

`build_static_callgraph.py` scanned existing Pass622 and Pass631 CSV, pcode, and disassembly exports for direct call edges, tail branches, `BRANCH`, `BRANCHIND`, and JMP-style edges.

- callgraph edges found: `111`
- Path B predecessor rows: `58`
- unique predecessor entries into Path B: `6`
- useful new receive predecessors: `0`

The predecessor set is either Path B internal, already rejected helper/init paths, process-entry/thunk paths, or unresolved helper branches with no recv/register handoff evidence.

### Phase 3 - Register Provenance

`trace_register_provenance.py` found no concrete source for:
- RDX context
- RSI base
- `[RBP+0]` PC offset
- initial/effective BL

The blocking tuple for bounded VM trace is still unavailable.

### Phase 4 - Context Struct / PC Offset Search

`inspect_context_offsets.py` found `13` context-like base/offset rows, including dispatcher `[RBP+0]`-style access candidates, but none resolves the RDX-backed context object or the actual PC offset value.

### Phase 5 - Bounded VM Trace Gate

`run_bounded_s2c_trace_if_ready.py` refused to run a trace because RSI base, `[RBP+0]`, and effective BL are not concrete. This avoids repeating broad BL brute force.

### Phase 6 - Future S2C Oracle Route

Created `future_s2c_oracle_scaffold.py`. It records only future oracle metadata locally and stores no payload bytes or hashes. It is ready for a future S2C known-plaintext frame if one is produced.

## Exact Missing Artifact Needed

A targeted Ghidra export is needed that starts from code references to the import thunk addresses for `recv`, `WSARecv`, and `recvfrom`, exports the actual wrapper functions containing those references, then exports one-level callers/callees from those wrappers. The decisive requirement is a concrete path from a receive wrapper into Path B with register setup for RDX, RSI, `[RBP+0]`, and BL/RBX.

Without that artifact, current static/offline evidence is exhausted for S2C initial key derivation.
