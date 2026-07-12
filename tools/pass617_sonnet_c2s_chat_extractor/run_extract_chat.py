"""
run_extract_chat.py
===================
CLI chat extractor for EuroAion world C2S captures.

Prints a clean per-frame timeline showing all decoded C2S packets
with CM_CHAT text highlighted.  No raw hex, no byte blobs.

Also writes local-only CSV logs and validates against KXSEQ oracle.

Usage:
    python run_extract_chat.py [path/to/capture.pcapng] [--verbose]

Default capture:
    C:\\AionTools\\aion_decoder_agent\\inbox\\captures\\startup_world_open_kxseq.pcapng
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from euroaion_c2s_chat_extractor import (
    ANCHOR_FRAME,
    ANCHOR_KEY_HEX,
    extract_c2s_chat,
)

DEFAULT_PCAP = Path(
    r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng"
)
OUTBOX = Path(
    r"C:\AionTools\aion_decoder_agent\outbox\pass617_sonnet_c2s_chat_extractor_local"
)

# KXSEQ oracle – ordered list of expected chat messages
KXSEQ_ORACLE: list[str] = [
    "KXSEQ_001",
    "KXSEQ_002_A",
    "KXSEQ_003_AA",
    "KXSEQ_004_AAA",
    "KXSEQ_005_AAAA",
    "KXSEQ_006_AAAAAAAA",
    "KXSEQ_007_AAAAAAAAAAAAAAAA",
    "KXSEQ_008_0123456789",
    "KXSEQ_009_ABABABABABABABAB",
    "KXSEQ_010_REPEAT",
    "KXSEQ_010_REPEAT",
]


def main() -> None:
    args    = sys.argv[1:]
    verbose = "--verbose" in args
    args    = [a for a in args if a != "--verbose"]
    pcap    = Path(args[0]) if args else DEFAULT_PCAP

    if not pcap.exists():
        print(f"ERROR: capture not found: {pcap}")
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()
    print(f"EuroAion C2S Chat Extractor")
    print(f"Capture : {pcap.name}")
    print(f"Anchor  : frame {ANCHOR_FRAME}  key {ANCHOR_KEY_HEX}")
    print(f"Run at  : {now}")
    print()

    result = extract_c2s_chat(pcap, verbose=verbose)

    # ── print chat timeline ───────────────────────────────────────────────────
    print(f"{'Frame':>6}  {'Rel-Time':>10}  {'C':1}  {'Opcode':<22}  {'Chat Text'}")
    print("-" * 80)
    for entry in result.entries:
        chat = f"  {entry.chat_text!r}" if entry.chat_text else ""
        comp = "✓" if entry.complement_ok else "✗"
        print(f"{entry.frame:>6}  {entry.timestamp:>10.3f}s  {comp}  "
              f"{entry.opcode_name:<22}{chat}")
    print()

    # ── KXSEQ oracle check ────────────────────────────────────────────────────
    extracted_texts = result.chat_texts
    found_count     = 0
    missing:  list[str] = []

    oracle_remaining = list(KXSEQ_ORACLE)
    for txt in extracted_texts:
        if oracle_remaining and txt == oracle_remaining[0]:
            oracle_remaining.pop(0)
            found_count += 1

    missing = oracle_remaining  # whatever wasn't consumed

    print(f"C2S packets processed : {result.c2s_packets_processed}")
    print(f"CM_CHAT packets seen  : {result.cm_chat_packets_seen}")
    print(f"Chat texts extracted  : {len(extracted_texts)}")
    print(f"KXSEQ oracle match    : {found_count}/{len(KXSEQ_ORACLE)}")
    if missing:
        print(f"Missing KXSEQ        : {missing}")
    if result.first_divergence:
        print(f"First divergence     : frame {result.first_divergence}")
    all_ok = len(missing) == 0

    print()
    print(f"All KXSEQ found: {'YES ✓' if all_ok else 'NO ✗'}")

    # ── write local-only files ────────────────────────────────────────────────
    OUTBOX.mkdir(parents=True, exist_ok=True)
    log_path   = OUTBOX / "full_run.log"
    chat_path  = OUTBOX / "extracted_chat_local.csv"
    trace_path = OUTBOX / "keyroll_trace_local.csv"

    # extracted_chat_local.csv
    with chat_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["frame", "rel_time_s", "opcode_name", "chat_text"])
        w.writeheader()
        for e in result.chat_entries:
            w.writerow({
                "frame":      e.frame,
                "rel_time_s": f"{e.timestamp:.3f}",
                "opcode_name": e.opcode_name,
                "chat_text":  e.chat_text or "",
            })

    # keyroll_trace_local.csv
    with trace_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["frame", "opcode", "opcode_name",
                                          "complement_ok", "update_type", "is_chat"])
        w.writeheader()
        for e in result.entries:
            w.writerow({
                "frame":        e.frame,
                "opcode":       f"0x{e.opcode:02X}",
                "opcode_name":  e.opcode_name,
                "complement_ok": "yes" if e.complement_ok else "no",
                "update_type":  e.update_type,
                "is_chat":      "yes" if e.is_chat else "no",
            })

    # full_run.log
    with log_path.open("w", encoding="utf-8") as f:
        f.write(f"run_extract_chat  {now}\n")
        f.write(f"capture: {pcap}\n\n")
        f.write(f"c2s_packets_processed : {result.c2s_packets_processed}\n")
        f.write(f"cm_chat_packets_seen  : {result.cm_chat_packets_seen}\n")
        f.write(f"chat_texts_extracted  : {len(extracted_texts)}\n")
        f.write(f"kxseq_found           : {found_count}/{len(KXSEQ_ORACLE)}\n")
        f.write(f"all_kxseq_found       : {all_ok}\n")
        if result.first_divergence:
            f.write(f"first_divergence      : frame {result.first_divergence}\n")
        f.write("\n-- chat timeline --\n")
        for e in result.entries:
            chat = f"  text={e.chat_text!r}" if e.chat_text else ""
            f.write(f"frame={e.frame:5}  {e.opcode_name:<22}{chat}\n")

    print()
    print(f"Local output: {OUTBOX}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
