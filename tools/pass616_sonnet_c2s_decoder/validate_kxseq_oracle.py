"""
validate_kxseq_oracle.py
========================
Oracle validator: decodes the KXSEQ capture and asserts exact plaintext
matches.  Exits 0 if all labels match, non-zero otherwise.

Also writes:
  C:\\AionTools\\aion_decoder_agent\\outbox\\pass616_sonnet_c2s_decoder_local\\
    full_decoder_run.log
    decoded_messages_local.csv    (local only - NOT committed to git)
    keyroll_trace_local.csv       (local only - NOT committed to git)

Usage:
    python validate_kxseq_oracle.py [path/to/capture.pcapng]
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from euroaion_c2s_decoder import (
    ANCHOR_FRAME,
    ANCHOR_KEY_HEX,
    OPCODE_CM_CHAT,
    decode_c2s_stream,
    decode_opcode,
)

DEFAULT_PCAP = Path(
    r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng"
)

OUTBOX = Path(
    r"C:\AionTools\aion_decoder_agent\outbox\pass616_sonnet_c2s_decoder_local"
)

# Ground-truth oracle
ORACLE: list[tuple[int, str]] = [
    (4329, "KXSEQ_001"),
    (4353, "KXSEQ_002_A"),
    (4360, "KXSEQ_003_AA"),
    (4389, "KXSEQ_004_AAA"),
    (4399, "KXSEQ_005_AAAA"),
    (4402, "KXSEQ_006_AAAAAAAA"),
    (4412, "KXSEQ_007_AAAAAAAAAAAAAAAA"),
    (4417, "KXSEQ_008_0123456789"),
    (4422, "KXSEQ_009_ABABABABABABABAB"),
    (4429, "KXSEQ_010_REPEAT"),
    (4435, "KXSEQ_010_REPEAT"),
]


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    if not pcap.exists():
        print(f"ERROR: capture not found: {pcap}")
        sys.exit(1)

    OUTBOX.mkdir(parents=True, exist_ok=True)
    log_path     = OUTBOX / "full_decoder_run.log"
    msgs_path    = OUTBOX / "decoded_messages_local.csv"
    trace_path   = OUTBOX / "keyroll_trace_local.csv"

    now = datetime.now(timezone.utc).isoformat()
    print(f"[{now}] validate_kxseq_oracle starting")
    print(f"  capture : {pcap}")

    packets, divergence = decode_c2s_stream(pcap, verbose=True)

    # ── collect results ───────────────────────────────────────────────────────
    oracle_map  = {frame: label for frame, label in ORACLE}
    chat_frames = {dp.frame: dp for dp in packets if dp.chat_text is not None}

    pass_count = 0
    fail_count = 0
    first_fail: int | None = None
    validation_rows: list[dict] = []

    for frame, expected in ORACLE:
        dp = chat_frames.get(frame)
        got = dp.chat_text if dp else None
        ok  = got == expected
        if ok:
            pass_count += 1
        else:
            fail_count += 1
            if first_fail is None:
                first_fail = frame
        validation_rows.append({
            "frame":          frame,
            "expected_label": expected,
            "recovered_text": got or "",
            "match":          "yes" if ok else "no",
        })
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  frame={frame}  expected={expected!r}  got={got!r}")

    # ── write local CSV files (NOT committed) ─────────────────────────────────
    # decoded_messages_local.csv – high-level, safe text only
    with msgs_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["frame", "opcode", "complement_ok", "chat_text"])
        w.writeheader()
        for dp in packets:
            w.writerow({
                "frame":         dp.frame,
                "opcode":        f"0x{dp.opcode:02X}",
                "complement_ok": "yes" if dp.complement_ok else "no",
                "chat_text":     dp.chat_text or "",
            })

    # keyroll_trace_local.csv – update type per frame (no key material)
    with trace_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["frame", "update_type", "opcode"])
        w.writeheader()
        for dp in packets:
            w.writerow({
                "frame":       dp.frame,
                "update_type": dp.update_type,
                "opcode":      f"0x{dp.opcode:02X}",
            })

    # full_decoder_run.log
    with log_path.open("w", encoding="utf-8") as f:
        f.write(f"validate_kxseq_oracle run at {now}\n")
        f.write(f"capture: {pcap}\n")
        f.write(f"packets decoded: {len(packets)}\n")
        f.write(f"ORACLE pass: {pass_count}/{len(ORACLE)}\n")
        if first_fail:
            f.write(f"first failure: frame {first_fail}\n")
        if divergence:
            f.write(f"first key-roll divergence: frame {divergence}\n")
        f.write("\n-- per-frame results --\n")
        for row in validation_rows:
            f.write(
                f"frame={row['frame']}  match={row['match']}  "
                f"expected={row['expected_label']!r}  got={row['recovered_text']!r}\n"
            )

    print()
    print(f"ORACLE result: {pass_count}/{len(ORACLE)} passed")
    if first_fail:
        print(f"First failure: frame {first_fail}")
    print(f"Local output: {OUTBOX}")

    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
