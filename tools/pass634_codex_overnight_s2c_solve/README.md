# Pass634 Overnight S2C Static Solve Tools

These tools consume existing local Ghidra/static export directories and emit Git-safe CSV summaries only. They do not run the game client, attach to a process, dump memory, or read PCAP payload bytes.

Primary inputs:
- `C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports`
- `C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs`

Scripts:
- `export_recv_import_wrappers.java`: targeted Ghidra Java exporter for recv/send/import thunk wrappers, for future static runs.
- `build_static_callgraph.py`: builds a direct/tail-call graph from exported CSV/pcode/disasm and intersects it with Path B.
- `trace_register_provenance.py`: summarizes static register provenance blockers for Path B registers.
- `inspect_context_offsets.py`: scans exported pcode/disasm/decompile text for context-like base+offset reads/writes.
- `run_bounded_s2c_trace_if_ready.py`: gates bounded VM trace execution; refuses to run unless RSI base, PC offset, and effective BL are concretely known.

No raw pcode/disassembly dumps are committed; only summaries and counts are written under `artifacts/pass634_codex_*`.
