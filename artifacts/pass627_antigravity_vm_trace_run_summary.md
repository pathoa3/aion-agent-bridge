# pass627 VM Trace Run Summary

## Status: REAL BYTECODE FOUND – VM trace operative

---

## Key Findings

### 1. Real .aion1 Bytecode Is Accessible

The first **455,184 bytes** of `.aion1` are present in the packed PE binary (`4.7.5.Game.dll.bin`), mapped to the `.reloc` section on disk at file offset `0x1471000`.

| Property | Value |
|---|---|
| File offset | `0x1471000` |
| VA range available | `0x11472000..0x114E2000` |
| Bytes available | 455,184 (445 KB) |
| Shannon entropy | 6.51 bits (structured bytecode, not compressed random) |
| Handler table accessible? | **NO** – table is above `0x114E2000` (packed) |

### 2. Dispatcher Mechanics Confirmed from Ghidra Pcode

From `FUN_11b5625b.pcode.txt` (pass622 export):

| Register | Role | Pcode Evidence |
|---|---|---|
| RBP (reg 0x28) | VM context pointer | `0x11B59343: RBP = RDX` in FUN_11b59337 |
| RSI (reg 0x30) | Bytecode instruction pointer | `0x11B562AE: RSI += LOAD[RBP]` |
| BL/BH (reg 0x18) | Opcode decryption key | `0x11B562CC: AL = AL - BL` (decrypt) |
| R12 (reg 0xa0) | Handler table base | `0x11B56278: R12 = const 0x11B54E6F` |
| RAX (reg 0x10) | Handler VA | `0x11B5630F: RAX = LOAD[R12 + AL*8]` |
| BRANCHIND | Handler dispatch | `0x11B56329: BRANCHIND RAX` |

### 3. Real Bytecode Trace (BL=0x00, first 32 bytes of .aion1)

Under `BL=0x00`, the first 32 bytes at VA `0x11472000` decode to 100% valid handlers with 4 promoted handler hits:

| Offset | VA | Raw | Op | Handler VA | Notes |
|---|---|---|---|---|---|
| 0 | 0x11472000 | 0x1E | 0x12 | 0x11B57363 | CMC |
| 1 | 0x11472001 | 0x36 | 0x5F | 0x11B5832F | **PROMOTED** (MOVZX EAX,AL) |
| 6 | 0x11472006 | 0x36 | 0xF7 | 0x11B57796 | **PROMOTED** (BT BX,0x9) |
| 13 | 0x1147200D | 0x37 | 0xBB | 0x11B57796 | **PROMOTED** (BT BX,0x9) |
| 14 | 0x1147200E | 0x45 | 0xD0 | 0x11B5932F | **PROMOTED** (SETZ AH) |

### 4. BL Sweep Results

- All 256 initial BL candidates tested against 128-byte real bytecode window
- **All 256** produce 100% valid .aion1 handler VAs (expected — all 256 opcodes are valid)
- Discrimination via promoted-handler hit rate: top candidates score ~18% promoted hits
- Best empirical BL from raw probe: `0x00` (100% valid, 4/32 promoted in first 32 bytes)

### 5. What Is NOT Found

- **S2C initial key**: Not found. The key is stored in the VM context struct (at `[RBP+offset]`) passed as `RDX` to `FUN_11b59337`. This struct is runtime-only.
- **S2C key derivation bytecode**: Not identified. Would require tracing the specific bytecode executed during the handshake packet receive path.

---

## Deliverables

| File | Purpose |
|---|---|
| `extract_handler_table.py` | Loads and validates Ghidra handler table (256/256 valid) |
| `locate_vm_bytecode_stream.py` | PE analysis — confirms 455 KB of real bytecode accessible |
| `run_vm_trace_candidates.py` | Sweeps all 256 BL values over real bytecode; scores/ranks |
| `artifacts/pass627_antigravity_trace_scores.csv` | 256-row BL sweep scores |
| `artifacts/pass627_antigravity_handler_table_status.csv` | Handler table validation |
| `artifacts/pass627_antigravity_bytecode_stream_candidates.csv` | Stream source candidates |

---

## Next Steps

1. Narrow the BL sweep to the bytes at a specific VM PC offset (e.g., the offset used during the S2C handshake receive path).
2. Cross-reference the promoted-handler hit sequence with the network receive handler in `FUN_11b45846`.
3. To find the S2C initial key: trace `FUN_11b59337` callers and identify what value is passed as `RDX` (the VM context struct pointer) during S2C packet receipt.
