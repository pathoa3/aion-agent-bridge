# Antigravity Report: pass635 Recv Wrapper Audit

## Status: STATIC PATH EXHAUSTED — ORACLE ROUTE IS NEXT

---

## Pass634 Export Failure Diagnosed and Fixed

- **Root cause:** Java script had UTF-8 BOM (`EF BB BF`), causing `GhidraScriptLoadException`
- **Fix:** Saved script without BOM for pass635
- **Result:** Ghidra headless ran successfully, exit 0, 5 CSV files produced

---

## Definitive Export Result

| File | Rows | Finding |
|---|---|---|
| `recv_import_symbols.csv` | 9 | All WS2_32 APIs present in import table |
| `recv_import_xrefs.csv` | 9 | **All DATA refs** — IAT slot pointers only |
| `recv_wrapper_edges.csv` | **0** | No call edges from any wrapper |
| `recv_wrapper_functions.csv` | **0** | No wrapper functions found by Ghidra |

**recv_related_caller_found = false**  
**path_b_intersections_found = 0**

---

## Why No Callers Are Visible (Definitive)

The `CALL [WSARecv]` / `CALL [recv]` instructions reside in the **packed `.aion1` section** (VA > `0x114E2000`). Ghidra cannot disassemble this packed region statically. Binary scan confirms zero IAT address patterns in the available PE bytes.

---

## Static Path Is Exhausted

All available offline evidence has been searched:
- 8 passes of Ghidra export and pcode analysis
- 111-edge callgraph — 0 recv-related predecessors
- Direct binary IAT scan — 0 hits
- Ghidra xref DB — 0 code callers for any socket API

**`static_path_exhausted = true`**

---

## Next Step: S2C Known-Plaintext Oracle

The `future_s2c_oracle_scaffold.py` (pass634) is ready.

**Needs:**
1. Frame number of an S2C packet with known plaintext (SM_VERSION / MOTD)
2. Exact UTF-16LE plaintext bytes
3. Raw encrypted bytes from PCAP

**Method:** `keystream[i] = plaintext[i] ^ ciphertext[i]` → recover effective BL → roll forward

This mirrors the C2S approach (pass616, 11/11 KXSEQ verified).

**`future_s2c_oracle_is_best_next_step = true`**
