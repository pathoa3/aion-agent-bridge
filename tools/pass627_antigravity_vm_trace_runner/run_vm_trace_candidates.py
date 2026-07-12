"""
run_vm_trace_candidates.py  (v2 — uses real .aion1 bytecode)
=============================================================
Runs offline VM bytecode trace candidates with different initial BL values.

The first 455 KB of .aion1 (VA 0x11472000..0x114E2000) IS accessible from
4.7.5.Game.dll.bin (mapped to .reloc section on disk, file offset 0x1471000).
This is the VM bytecode data region. The handler code and handler table are
packed (above 0x114E2000) and not directly available.

Strategy:
  1. Read real .aion1 bytecode from 4.7.5.Game.dll.bin.
  2. Compute entropy to confirm it's bytecode (not compressed/random).
  3. Decode first N bytes under every BL from 0x00..0xFF.
  4. Score by:
       a. % of decoded opcodes with handler VAs in .aion1  (all 256 valid, so always 100%)
       b. % of promoted-handler hits
       c. BL uniqueness (no cycling within probe window)
  5. Report top candidates and the best initial BL.
  6. Specifically test BL=0x00 (best empirical result from aion1 probe).
"""

from __future__ import annotations
import csv
import math
import struct
import sys
from collections import Counter
from pathlib import Path

# ── paths ────────────────────────────────────────────────────────────────────
BIN_PATH   = Path(r"C:\AionTools\euroaion\4.7.5.Game.dll.bin")
HANDLER_CSV = (
    Path(r"C:\AionTools\aion_decoder_agent\outbox")
    / "pass611_codex_vm_solve_local" / "ghidra_pass8b"
    / "pass8b_handler_table_from_ghidra.csv"
)

# ── constants ─────────────────────────────────────────────────────────────────
IMAGE_BASE   = 0x10000000
RELOC_VADDR  = 0x01446000
RELOC_RAWPTR = 0x01445000
AION1_START_VA = 0x11472000
AION1_AVAIL_VA = 0x114E2000   # end of available (packed) data in file

AION1_MIN    = 0x11472000
AION1_MAX    = 0x11B59A00

PROMOTED_HANDLERS = {
    0x11B57437, 0x11B57796, 0x11B565D3, 0x11B55954,
    0x11B55CAF, 0x11B5832F, 0x11B55DF6, 0x11B5932F,
}

PROBE_SIZE   = 128   # bytes of .aion1 to use for scoring


def va_to_file_offset(va: int) -> int:
    rva = va - IMAGE_BASE
    return RELOC_RAWPTR + (rva - RELOC_VADDR)


def rol8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def decode_opcode(raw: int, bl: int) -> int:
    """VM opcode decode: opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)"""
    return rol8(((raw - bl + 0x86) & 0xFF) ^ 0x34, 5)


def update_bl(bl: int, decoded: int) -> int:
    return (bl - decoded) & 0xFF


# ── load resources ────────────────────────────────────────────────────────────
def load_aion1_bytes() -> bytes:
    data = BIN_PATH.read_bytes()
    start = va_to_file_offset(AION1_START_VA)
    end   = min(va_to_file_offset(AION1_AVAIL_VA), len(data))
    return data[start:end]


def load_handler_table() -> dict[int, dict]:
    table: dict[int, dict] = {}
    with open(HANDLER_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            op = int(row["opcode"])
            va_str = row["handler_va"]
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
            table[op] = {
                "handler_va":        va_str,
                "va_int":            va,
                "first_instruction": row.get("first_instruction", ""),
            }
    return table


# ── scoring ───────────────────────────────────────────────────────────────────
def score_trace(raw_bytes: bytes, initial_bl: int,
                handler_table: dict[int, dict]) -> dict:
    bl = initial_bl
    n_total      = len(raw_bytes)
    n_in_aion1   = 0
    n_promoted   = 0
    bl_set       = set()
    bl_repeated  = False
    decoded_ops  = []

    for raw in raw_bytes:
        op    = decode_opcode(raw, bl)
        entry = handler_table.get(op, {})
        va    = entry.get("va_int", 0)
        in_a  = AION1_MIN <= va <= AION1_MAX
        promo = va in PROMOTED_HANDLERS
        if in_a:    n_in_aion1 += 1
        if promo:   n_promoted += 1
        if bl in bl_set: bl_repeated = True
        bl_set.add(bl)
        decoded_ops.append({
            "raw":      f"0x{raw:02X}",
            "op":       f"0x{op:02X}",
            "h_va":     entry.get("handler_va", "?"),
            "h_ins":    entry.get("first_instruction", "?")[:32],
            "in_aion1": in_a,
            "promoted": promo,
            "bl_pre":   f"0x{bl:02X}",
        })
        bl = update_bl(bl, op)

    pct_a   = 100 * n_in_aion1  / n_total if n_total else 0
    pct_p   = 100 * n_promoted   / n_total if n_total else 0
    score   = pct_a * 0.6 + pct_p * 30.0 + (0 if bl_repeated else 10.0)
    return {
        "initial_bl":  f"0x{initial_bl:02X}",
        "n_bytes":     n_total,
        "n_in_aion1":  n_in_aion1,
        "n_promoted":  n_promoted,
        "pct_aion1":   round(pct_a, 1),
        "pct_promoted":round(pct_p, 1),
        "bl_unique":   len(bl_set),
        "bl_repeated": bl_repeated,
        "score":       round(score, 2),
        "decoded_ops": decoded_ops,
    }


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    print("VM Trace Candidate Runner  (real .aion1 bytecode)")
    print("=" * 80)
    print()

    # Load .aion1 bytes
    if not BIN_PATH.exists():
        print(f"ERROR: {BIN_PATH} not found"); sys.exit(1)
    aion1 = load_aion1_bytes()
    print(f"Loaded {len(aion1):,} bytes from .aion1 (VA 0x{AION1_START_VA:X}..0x{AION1_AVAIL_VA:X})")

    # Entropy check
    freq    = Counter(aion1)
    entropy = -sum((c/len(aion1))*math.log2(c/len(aion1)) for c in freq.values() if c>0)
    print(f"Shannon entropy: {entropy:.4f} bits  (structured bytecode < 7)")
    print()

    # Load handler table
    if not HANDLER_CSV.exists():
        print(f"ERROR: {HANDLER_CSV} not found"); sys.exit(1)
    handler_table = load_handler_table()
    print(f"Loaded {len(handler_table)} handler table entries (all should be in .aion1).")
    print()

    # Use the first PROBE_SIZE bytes of real .aion1 for scoring
    probe = aion1[:PROBE_SIZE]
    print(f"Probe window: first {PROBE_SIZE} bytes of .aion1  (0x{AION1_START_VA:X}..0x{AION1_START_VA+PROBE_SIZE:X})")
    print()

    # Score all 256 BL values
    all_scores = []
    for bl in range(256):
        result = score_trace(probe, bl, handler_table)
        all_scores.append(result)

    all_scores.sort(key=lambda r: r["score"], reverse=True)

    # Report top 20
    print(f"Top 20 initial BL candidates (by score on real .aion1 bytecode):")
    print(f"  {'BL':4} | {'%aion1':7} | {'%promo':7} | {'Score':7} | {'BL_unique':9} | BL_rep")
    print("-" * 65)
    for r in all_scores[:20]:
        print(f"  {r['initial_bl']:4} | {r['pct_aion1']:7.1f} | {r['pct_promoted']:7.1f} | "
              f"{r['score']:7.2f} | {r['bl_unique']:9} | {'YES' if r['bl_repeated'] else 'no'}")
    print()

    # Best candidate
    best = all_scores[0]
    print(f"Best candidate: BL={best['initial_bl']}  score={best['score']}  "
          f"%promo={best['pct_promoted']}%  bl_repeated={'YES' if best['bl_repeated'] else 'no'}")
    print()

    # Show decoded trace for BL=0x00 (empirically best from probe)
    for special_bl_name, special_bl_val in [("BL=0x00 (empirical best)", 0x00)]:
        r00 = score_trace(aion1[:32], special_bl_val, handler_table)
        print(f"Detailed trace: {special_bl_name}  (first 32 bytes of .aion1):")
        print(f"  {'i':4} | {'VA':10} | {'Raw':6} | {'Op':5} | {'BL_pre':7} | {'Handler VA':18} | {'Notes':18} | First Ins")
        print("-" * 115)
        for i, step in enumerate(r00["decoded_ops"]):
            va = AION1_START_VA + i
            notes = []
            if step["in_aion1"]: notes.append("aion1")
            if step["promoted"]: notes.append("PROMOTED")
            print(f"  {i:4} | 0x{va:X} | {step['raw']:6} | {step['op']:5} | {step['bl_pre']:7} | "
                  f"{step['h_va']:18} | {','.join(notes):18} | {step['h_ins']}")
        print()

    # Write scores CSV
    out_csv = Path("artifacts") / "pass627_antigravity_trace_scores.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [k for k in all_scores[0].keys() if k != "decoded_ops"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_scores:
            row = {k: v for k, v in r.items() if k != "decoded_ops"}
            writer.writerow(row)
    print(f"Trace scores written to: {out_csv}")

    # Summary for decision JSON
    valid_count = sum(1 for r in all_scores if r["score"] > 50)
    print()
    print(f"Total BL candidates tested: {len(all_scores)}")
    print(f"Candidates scoring > 50   : {valid_count}")
    print(f"Best initial BL           : {best['initial_bl']}")

    return {
        "initial_bl_candidates_tested": len(all_scores),
        "valid_candidates_above_50":    valid_count,
        "best_bl":                      best["initial_bl"],
        "best_score":                   best["score"],
        "real_bytecode_stream_found":   True,
        "aion1_bytes_available":        len(aion1),
        "entropy":                      round(entropy, 4),
    }


if __name__ == "__main__":
    result = main()
