#!/usr/bin/env python3
"""Find likely key-slot writes in local-only Pass622 Ghidra p-code/disassembly exports."""

import argparse
import csv
import re
from pathlib import Path

WRITE_RE = re.compile(r"\b(STORE|MOV)\b", re.I)
KEY_HINT_RE = re.compile(r"(QWORD|:8|\(8\)|INT_XOR|INT_ADD|INT_MULT|seed|key|recv|packet|context)", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default=r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
    ap.add_argument("--out", default=r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports\keyslot_write_scan.csv")
    ns = ap.parse_args()
    rows = []
    for path in Path(ns.export_dir).glob("*.pcode.txt"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if WRITE_RE.search(line) and KEY_HINT_RE.search(line):
                rows.append({"file": path.name, "line": lineno, "pattern": "write+key_hint", "excerpt": line[:220]})
    out = Path(ns.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "line", "pattern", "excerpt"])
        writer.writeheader()
        writer.writerows(rows)
    print("keyslot write scan rows=%d out=%s" % (len(rows), out))


if __name__ == "__main__":
    main()
