# Pass662 Explicit Register Live-ins

Scope: four functions only, explicit RCX/RDX/R8/R9/RSI/RDI/RBP/R12-R15 register live-ins.

Ghidra exit code: 0
New local files: 11
Registers found: 11
Explicit RCX/RDX/R8/R9 mapping success: False
Context/buffer candidate found: False
Initializer/decoder generated: False

Blocker/next: use Ghidra register varnode synthesis at the target function entry (Varnode(registerAddress,size)) and query HighFunction symbol/cover intersections for RCX/RDX/R8/R9, because enumerating HighFunction pcode varnodes did not produce matching live-in register varnodes

No raw p-code/decompile, packet bytes, keys/state, binaries, captures, or memory values were committed.
