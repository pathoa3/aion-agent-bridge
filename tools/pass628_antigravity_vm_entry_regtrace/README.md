# pass628 VM Entry Register Trace

Static pcode analysis of VM dispatcher entry register initialization.

---

## Tools

| File | Purpose |
|---|---|
| `trace_dispatcher_entry_registers.py` | Parses exported pcode traces for all caller functions; builds register propagation table |
| `README.md` | This file |

## Usage

```cmd
cd C:\AionTools\aion-agent-bridge
python tools\pass628_antigravity_vm_entry_regtrace\trace_dispatcher_entry_registers.py
```

Outputs: `artifacts/pass628_antigravity_register_sources.csv`, `artifacts/pass628_antigravity_dispatcher_entry_candidates.csv`

---

## Key Findings

### PATH A (FUN_11b5863d -> FUN_11b56b2c -> FUN_11b5625b)
- **RSI = RBP** at `0x11B56B4B` in `FUN_11b56b2c` — bytecode base = context pointer
- **RBP = RSP** at `0x11B56B8D` before dispatch — stack frame base becomes context
- RSP -= 0x140 at `0x11B56B97` before `BRANCH 0x11B5625B`

### PATH B (FUN_11b45846 -> FUN_11b56999 -> FUN_11b59337 -> FUN_11b59838 -> FUN_11b5625b)
- **RBP = RDX** at `0x11B59343` in `FUN_11b59337` — context pointer = 2nd call arg
- RBP byte-swapped at `0x11B5934B` (obfuscation)
- **BL** comes from caller's RBX, preserved via PUSH at FUN_11b59337 entry

### Dispatcher (FUN_11b5625b)
- **R12** = `0x11B54E6F` hardcoded at `0x11B56278`
- **RSI += LOAD[RBP]** at `0x11B562AE` (PC offset from context struct)
- **Decode**: `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`
- **Dispatch**: `BRANCHIND RAX` at `0x11B56329`

---

## Missing for Full Trace

1. `FUN_11b5863d` pcode — RBP at entry to FUN_11b56b2c (PATH A RSI base)
2. Entry caller pcode — what RDX holds when FUN_11b45846 is entered (PATH B context)
3. Context struct layout — what is at `[RBP+0]` (PC offset field)
4. Initial BL value — from caller of FUN_11b45846 chain
