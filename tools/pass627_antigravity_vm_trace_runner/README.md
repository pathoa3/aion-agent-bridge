# pass627 VM Trace Runner

Static/offline VM bytecode trace runner using real .aion1 bytecode from the packed PE binary.

---

## Key Discovery

The first **455,184 bytes** of the `.aion1` section are readable directly from `4.7.5.Game.dll.bin`.
This region (`VA 0x11472000..0x114E2000`) contains VM bytecode data.
The handler table and handler code (`0x11B54E6F+`) are in the upper .aion1 range and remain packed.

---

## Files

| File | Purpose |
|---|---|
| `extract_handler_table.py` | Load and validate Ghidra handler table CSV |
| `locate_vm_bytecode_stream.py` | Analyze PE sections; confirm bytecode accessibility |
| `run_vm_trace_candidates.py` | Sweep all 256 BL values over real bytecode; score/rank |
| `README.md` | This file |

---

## Usage

```cmd
cd C:\AionTools\aion-agent-bridge

# Validate handler table (256 entries, all in .aion1)
python tools\pass627_antigravity_vm_trace_runner\extract_handler_table.py

# Locate and report bytecode stream sources
python tools\pass627_antigravity_vm_trace_runner\locate_vm_bytecode_stream.py

# Run BL sweep over real .aion1 bytecode
python tools\pass627_antigravity_vm_trace_runner\run_vm_trace_candidates.py
```

---

## Dispatcher Facts (from Ghidra pcode)

- **R12** = `0x11B54E6F` (handler table base) — hardcoded at `0x11B56278`
- **RSI** = bytecode pointer, init via `RSI += LOAD[RBP]` at `0x11B562AE`
- **BL** = opcode decryption key, passed in `RBX` from caller
- **Decode**: `opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)`
- **BL update**: `BL = (BL - opcode) & 0xFF`
- **Dispatch**: `BRANCHIND RAX` at `0x11B56329`
