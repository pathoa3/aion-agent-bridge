# Pass659 Targeted Native Context Trace

World port detected: 7780
Targeted export ran: True
New targeted files: 129
Seeds resolved: 7
Pass623 stack-save rejections applied: True
Initializer candidates: 0
Exact known message validated: False
Acceptance gate passed: False

The targeted Ghidra export was actually invoked against the existing project and generated local-only outputs. The rejected RSP stack-save candidates remain closed. The remaining blocker is the exact callsite SSA/def-use relation from VM context/receive input into a non-stack persistent S2C state field.

No raw exports, p-code, decompile text, packet bytes, decoded bytes, keys, masks, states, captures, or packet hashes were committed.
