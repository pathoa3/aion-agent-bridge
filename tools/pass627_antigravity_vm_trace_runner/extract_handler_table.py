"""
extract_handler_table.py
========================
Loads and validates the Ghidra-exported VM handler table.
Source: pass8b_handler_table_from_ghidra.csv (from pass611/pass8b)
Returns summary statistics and top entries.

Usage:
  python extract_handler_table.py [--csv PATH] [--out PATH]

Defaults:
  --csv  C:\\AionTools\\aion_decoder_agent\\outbox\\pass611_codex_vm_solve_local\\ghidra_pass8b\\pass8b_handler_table_from_ghidra.csv
  --out  handler_table_validated.csv
"""

from __future__ import annotations
import argparse
import csv
import sys
from pathlib import Path

HANDLER_TABLE_VA   = 0x11B54E6F
HANDLER_FORMULA_K  = 0x15F664FE   # int64([table + op*8]) + K = handler_va
AION1_MIN          = 0x11472000
AION1_MAX          = 0x11B59A00


def rol8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def decode_opcode(raw: int, bl: int) -> int:
    """Full dispatcher opcode decode formula."""
    return rol8(((raw - bl + 0x86) & 0xFF) ^ 0x34, 5)


def update_bl(bl: int, decoded: int) -> int:
    return (bl - decoded) & 0xFF


def load_handler_table(csv_path: Path) -> list[dict]:
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def validate_handler_table(rows: list[dict]) -> tuple[list[dict], int, int]:
    """
    Validates handler VAs are within .aion1 range.
    Returns (validated_rows, valid_count, invalid_count).
    """
    validated = []
    valid = 0
    invalid = 0
    for row in rows:
        va_str = row.get("handler_va", "0")
        try:
            va = int(va_str, 16) if va_str.startswith("0x") else int(va_str)
        except ValueError:
            va = 0
        in_range = AION1_MIN <= va <= AION1_MAX
        row["va_int"] = va
        row["in_aion1"] = in_range
        validated.append(row)
        if in_range:
            valid += 1
        else:
            invalid += 1
    return validated, valid, invalid


def print_summary(rows: list[dict], valid: int, invalid: int):
    print("Handler Table Validation Summary")
    print("=" * 60)
    print(f"  Total entries : {len(rows)}")
    print(f"  Valid (.aion1): {valid}")
    print(f"  Invalid       : {invalid}")
    print(f"  Table base VA : 0x{HANDLER_TABLE_VA:X}")
    print(f"  Formula const : +0x{HANDLER_FORMULA_K:X}")
    print()
    print("Sample entries (first 10):")
    print(f"  {'Opcode':6} | {'Handler VA':14} | {'First Instruction':30} | In .aion1")
    print("-" * 80)
    for row in rows[:10]:
        op  = row.get("opcode", "?")
        va  = row.get("handler_va", "?")
        ins = row.get("first_instruction", "?")[:30]
        ok  = row.get("in_aion1", False)
        print(f"  {op:6} | {va:14} | {ins:30} | {'YES' if ok else 'NO'}")
    print()


def main():
    default_csv = (
        Path(r"C:\AionTools\aion_decoder_agent\outbox")
        / "pass611_codex_vm_solve_local"
        / "ghidra_pass8b"
        / "pass8b_handler_table_from_ghidra.csv"
    )
    # Fallback: inbox copy
    fallback_csv = Path(r"C:\AionTools\aion_decoder_agent\inbox") / "pass8b_handler_table_from_ghidra.csv"

    parser = argparse.ArgumentParser(description="Validate Ghidra VM handler table")
    parser.add_argument("--csv", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("handler_table_validated.csv"))
    args = parser.parse_args()

    csv_path = args.csv
    if csv_path is None:
        if default_csv.exists():
            csv_path = default_csv
        elif fallback_csv.exists():
            csv_path = fallback_csv
        else:
            print(f"ERROR: handler table CSV not found at expected paths:")
            print(f"  {default_csv}")
            print(f"  {fallback_csv}")
            sys.exit(1)

    print(f"Loading handler table: {csv_path}")
    rows = load_handler_table(csv_path)
    validated, valid, invalid = validate_handler_table(rows)
    print_summary(validated, valid, invalid)

    # Write validated output
    out_path = args.out
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = list(rows[0].keys()) + ["in_aion1"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in validated:
            writer.writerow(row)
    print(f"Validated table written to: {out_path}")
    return valid, len(rows)


if __name__ == "__main__":
    main()
