from __future__ import annotations

import csv
import json
from pathlib import Path

from common import ART, PRIVATE, STATIC_KEY, ORACLE_MESSAGES, read_csv, write_csv


def rolling_decode(data: bytes, key32: int, offset: int, include_prev: bool, update_size: bool) -> bytes:
    key64 = (key32 & 0xFFFFFFFF) | 0x87546CA100000000
    if update_size:
        key64 = (key64 + max(0, len(data) - offset)) & 0xFFFFFFFFFFFFFFFF
    key = key64.to_bytes(8, "little")
    out = bytearray(data)
    if offset >= len(out):
        return bytes(out)
    prev = out[offset]
    out[offset] ^= key[0]
    for pos in range(offset + 1, len(out)):
        i = pos - offset
        cur = out[pos]
        mask = STATIC_KEY[i & 0x3F] ^ key[i & 0x7]
        if include_prev:
            mask ^= prev
        out[pos] ^= mask
        prev = cur
    return bytes(out)


def identity(data: bytes, *_args) -> bytes:
    return data


def main() -> None:
    frames = read_csv(ART / "pass607_codex_oracle_frames.csv")
    messages = [r["message"] for r in frames] or ORACLE_MESSAGES
    needles = [m.encode("utf-16le") for m in messages]
    base_keys = {
        "identity_control": 0,
        "pass590_false_key_0xfe683cb9": 0xFE683CB9,
        "pass590_variant_a_0x73e79463": 0x73E79463,
        "pass590_variant_b_0x73e78b35": 0x73E78B35,
        "aion_unique_deobf_cd92e451_3ff2cc87": ((0xFE683CB9 - 0x3FF2CC87) ^ 0xCD92E451) & 0xFFFFFFFF,
        "rydiik_deobf_cd92e4df_3ff2cccf": ((0xFE683CB9 - 0x3FF2CCCF) ^ 0xCD92E4DF) & 0xFFFFFFFF,
    }
    variants = []
    for name, key in base_keys.items():
        if name == "identity_control":
            variants.append((name, key, 0, False, False, identity))
            continue
        for offset in (0, 2, 8, 10):
            for include_prev in (False, True):
                for update_size in (False, True):
                    variants.append((name, key, offset, include_prev, update_size, rolling_decode))
    rows = []
    exact_count = 0
    contain_count = 0
    recovered: list[str] = []
    for frame in frames:
        payload = bytes.fromhex(frame["raw_tcp_payload_hex"])
        oracle_msg = frame["message"]
        oracle_plain = oracle_msg.encode("utf-16le")
        for name, key, offset, include_prev, update_size, func in variants:
            decoded = func(payload, key, offset, include_prev, update_size)
            exact = decoded == oracle_plain
            matches = [m for m, n in zip(messages, needles) if n in decoded]
            exact_count += int(exact)
            contain_count += int(bool(matches))
            if exact:
                recovered.append(oracle_msg)
            rows.append({
                "variant": name,
                "source_evidence": "public_reference_or_source_truthing_control",
                "offset": offset,
                "include_previous_byte_chaining": "yes" if include_prev else "no",
                "packet_size_key_update": "yes" if update_size else "no",
                "frame_number": frame["actual_wireshark_frame_number_if_available"],
                "oracle_message": oracle_msg,
                "payload_len": len(payload),
                "exact_oracle_match": "yes" if exact else "no",
                "utf16le_containment": "yes" if matches else "no",
                "matched_messages": "|".join(matches),
                "decoded_prefix_hex": decoded[:96].hex(),
                "decoded_prefix_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in decoded[:96]),
            })
    write_csv(ART / "pass607_codex_decoder_attempts.csv", rows)
    summary = [
        "# Pass607 Codex Decoder Summary",
        "",
        f"- corrected oracle frames tested: {len(frames)}",
        f"- bounded public/source variants tested per frame: {len(variants)}",
        f"- total attempts: {len(rows)}",
        f"- exact oracle matches: {exact_count}",
        f"- UTF-16LE containment matches: {contain_count}",
        "- no unbounded brute force, live process, debugger, memory dump, injection, anti-cheat bypass, or packet injection used.",
    ]
    (ART / "pass607_codex_decoder_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    if exact_count >= len(frames):
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(recovered) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps({"decoder_success": True, "frames": len(frames)}, indent=2), encoding="utf-8")
    print(f"attempts={len(rows)} exact={exact_count} containment={contain_count}")


if __name__ == "__main__":
    main()
