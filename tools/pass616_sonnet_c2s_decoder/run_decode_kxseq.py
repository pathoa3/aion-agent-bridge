"""
run_decode_kxseq.py
===================
Run the EuroAion C2S decoder against the KXSEQ capture and print a clean
per-frame summary.  No raw hex, no byte blobs, no key material in output.

Usage:
    python run_decode_kxseq.py [path/to/capture.pcapng]

Default capture:
    C:\\AionTools\\aion_decoder_agent\\inbox\\captures\\startup_world_open_kxseq.pcapng
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root or the tool directory
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from euroaion_c2s_decoder import (
    ANCHOR_FRAME,
    ANCHOR_KEY_HEX,
    OPCODE_CM_CHAT,
    decode_c2s_stream,
)

DEFAULT_PCAP = Path(
    r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng"
)

# Known KXSEQ target frames and their expected labels
KXSEQ_TARGETS: dict[int, str] = {
    4329: "KXSEQ_001",
    4353: "KXSEQ_002_A",
    4360: "KXSEQ_003_AA",
    4389: "KXSEQ_004_AAA",
    4399: "KXSEQ_005_AAAA",
    4402: "KXSEQ_006_AAAAAAAA",
    4412: "KXSEQ_007_AAAAAAAAAAAAAAAA",
    4417: "KXSEQ_008_0123456789",
    4422: "KXSEQ_009_ABABABABABABABAB",
    4429: "KXSEQ_010_REPEAT",
    4435: "KXSEQ_010_REPEAT",
}

OPCODE_NAMES = {
    0x53: "CM_CHAT",
    0x3E: "CM_VERSION_CHOOSE",
    0x0B: "CM_PING",
    0x3C: "CM_LEVEL_READY",
    0x26: "CM_ENTER_WORLD_READY",
    0x77: "CM_CHAT_MAC",
    0x71: "CM_PING_ALT",
    0x07: "CM_PING_B",
    0x00: "CM_PING_C",
    0x01: "CM_PING_D",
}


def opcode_label(op: int) -> str:
    return OPCODE_NAMES.get(op, f"0x{op:02X}")


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    if not pcap.exists():
        print(f"ERROR: capture not found: {pcap}")
        sys.exit(1)

    print(f"EuroAion C2S KXSEQ Decoder")
    print(f"Capture : {pcap.name}")
    print(f"Anchor  : frame {ANCHOR_FRAME}  key {ANCHOR_KEY_HEX}")
    print()

    packets, divergence = decode_c2s_stream(pcap, verbose=False)

    if not packets:
        print("ERROR: No packets decoded.")
        sys.exit(1)

    # Print header
    print(f"{'Frame':>6}  {'Opcode':<22}  {'Comp':>4}  {'Chat Text / Notes'}")
    print("-" * 80)

    recovered: dict[int, str] = {}

    for dp in packets:
        comp = "OK" if dp.complement_ok else "!!"
        op_label = opcode_label(dp.opcode)

        if dp.chat_text is not None:
            note = f"text={dp.chat_text!r}"
            if dp.frame in KXSEQ_TARGETS:
                expected = KXSEQ_TARGETS[dp.frame]
                if dp.chat_text == expected:
                    note += "  [MATCH]"
                    recovered[dp.frame] = dp.chat_text
                else:
                    note += f"  [MISMATCH expected={expected!r}]"
        else:
            note = dp.update_type

        print(f"{dp.frame:>6}  {op_label:<22}  {comp:>4}  {note}")

    print()
    print("=" * 80)
    print(f"KXSEQ Validation Summary")
    print("-" * 80)
    all_ok = True
    for frame, label in KXSEQ_TARGETS.items():
        got = recovered.get(frame)
        status = "PASS" if got == label else "FAIL"
        if status == "FAIL":
            all_ok = False
        print(f"  frame={frame:5}  {status}  expected={label!r}  got={got!r}")

    print()
    print(f"All KXSEQ recovered: {'YES' if all_ok else 'NO'}")
    if divergence:
        print(f"First divergence frame: {divergence}")
    if not all_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
