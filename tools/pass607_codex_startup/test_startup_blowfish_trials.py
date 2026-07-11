from __future__ import annotations

import json

from blowfish_pure import Blowfish
from pass607_codex_startup_common import (
    ART,
    EXPECTED_SMKEY,
    MASK7,
    STARTUP_LOG,
    STARTUP_PCAP,
    parse_log_messages,
    public_xorpass,
    spaced_hex,
    tcp_payload_rows,
    validate_plain,
    write_csv,
    xor_repeat,
)


TAIL_LE = bytes.fromhex("a16c5487")
TAIL_BE = bytes.fromhex("87546ca1")


def decrypt_aligned_region(data: bytes, key8: bytes, skip: int) -> tuple[bytes, int, int, int]:
    if skip >= len(data):
        return data, skip, 0, len(data)
    block_len = ((len(data) - skip) // 8) * 8
    if block_len <= 0:
        return data, skip, 0, len(data) - skip
    bf = Blowfish(key8)
    mid = bf.decrypt_ecb(data[skip:skip + block_len])
    return data[:skip] + mid + data[skip + block_len:], skip, block_len, len(data) - skip - block_len


def blowfish_then_xor(data: bytes, key8: bytes, skip: int, xor_offset: int, preupdate: bool) -> tuple[bytes, str]:
    dec, _start, block_len, tail = decrypt_aligned_region(data, key8, skip)
    dec = public_xorpass(dec, key8, offset=xor_offset, include_prev=True, update_size_before=preupdate)
    return dec, f"bf_skip={skip};bf_block_len={block_len};bf_tail={tail};xor_offset={xor_offset};preupdate={int(preupdate)}"


def xor_then_blowfish(data: bytes, key8: bytes, skip: int, xor_offset: int, preupdate: bool) -> tuple[bytes, str]:
    x = public_xorpass(data, key8, offset=xor_offset, include_prev=True, update_size_before=preupdate)
    dec, _start, block_len, tail = decrypt_aligned_region(x, key8, skip)
    return dec, f"xor_offset={xor_offset};preupdate={int(preupdate)};bf_skip={skip};bf_block_len={block_len};bf_tail={tail}"


def marker_shape(decoded: bytes) -> str:
    text = decoded.decode("utf-16le", errors="ignore")
    flags = []
    if "KX" in text or "KSTART" in text or "KXBOOT" in text:
        flags.append("markerish_text")
    if "/say" in text.lower():
        flags.append("say_text")
    if decoded.count(b"\x00") >= max(2, len(decoded) // 5):
        flags.append("many_nuls")
    return "|".join(flags)


def utf16_printable_ratio(decoded: bytes) -> float:
    if len(decoded) < 2:
        return 0.0
    chars = decoded[:len(decoded) - (len(decoded) % 2)].decode("utf-16le", errors="ignore")
    if not chars:
        return 0.0
    printable = sum(1 for c in chars if c.isprintable())
    return printable / len(chars)


def main() -> None:
    rows = tcp_payload_rows(STARTUP_PCAP)
    p9741 = next((r for r in rows if int(r["packet_no"]) == 9741), None)
    if not p9741:
        raise SystemExit("packet 9741 not found")
    decoded_smkey = xor_repeat(p9741["payload"], MASK7)
    smkey_ok = decoded_smkey == EXPECTED_SMKEY
    seed = decoded_smkey[7:11]
    keys = {
        "seed_le_tail_le": seed + TAIL_LE,
        "seed_be_tail_le": seed[::-1] + TAIL_LE,
        "seed_le_tail_be": seed + TAIL_BE,
        "seed_be_tail_be": seed[::-1] + TAIL_BE,
    }
    markers = parse_log_messages(STARTUP_LOG)
    for extra in ["KSTART_001", "KXBOOT_SAY_01", "KXBOOT_SAY_02_AAAAAAAAAAAAAAAA", "KXBOOT_SAY_03_1234567890"]:
        if extra not in markers:
            markers.append(extra)
    flow = p9741["flow"]
    packets = [r for r in rows if r["flow"] == flow and int(r["packet_no"]) > 9741 and int(r["payload_len"]) > 0]
    trial_rows = []
    for pkt in packets:
        payload = pkt["payload"]
        for key_name, key8 in keys.items():
            for skip in (0, 2, 4):
                dec, start, block_len, tail = decrypt_aligned_region(payload, key8, skip)
                v = validate_plain(dec, markers)
                trial_rows.append({
                    "packet_no": pkt["packet_no"],
                    "tcp_stream": pkt["tcp_stream"],
                    "flow": pkt["flow"],
                    "direction": pkt["direction"],
                    "payload_len": len(payload),
                    "payload_hex": payload.hex(),
                    "key_name": key_name,
                    "key8_hex": key8.hex(),
                    "order_variant": "Blowfish_ECB_decrypt_only",
                    "skip_bytes": skip,
                    "length_field_mode": "included" if skip == 0 else "excluded_or_prefix_preserved",
                    "block_bytes_decrypted": block_len,
                    "tail_bytes_preserved": tail,
                    "provider": "pure_python",
                    "packet_9741_smkey_confirmed": "yes" if smkey_ok else "no",
                    "derived_seed_hex": seed.hex(),
                    "utf16_printable_ratio": f"{utf16_printable_ratio(dec):.3f}",
                    "marker_shape": marker_shape(dec),
                    **v,
                })
                for xor_offset in (0, 2, 4):
                    for preupdate in (False, True):
                        for order in ("Blowfish_then_XORpass", "XORpass_then_Blowfish"):
                            if order == "Blowfish_then_XORpass":
                                dec2, notes = blowfish_then_xor(payload, key8, skip, xor_offset, preupdate)
                            else:
                                dec2, notes = xor_then_blowfish(payload, key8, skip, xor_offset, preupdate)
                            v2 = validate_plain(dec2, markers)
                            trial_rows.append({
                                "packet_no": pkt["packet_no"],
                                "tcp_stream": pkt["tcp_stream"],
                                "flow": pkt["flow"],
                                "direction": pkt["direction"],
                                "payload_len": len(payload),
                                "payload_hex": payload.hex(),
                                "key_name": key_name,
                                "key8_hex": key8.hex(),
                                "order_variant": order,
                                "skip_bytes": skip,
                                "length_field_mode": "included" if skip == 0 else "excluded_or_prefix_preserved",
                                "block_bytes_decrypted": notes,
                                "tail_bytes_preserved": "see_notes",
                                "provider": "pure_python",
                                "packet_9741_smkey_confirmed": "yes" if smkey_ok else "no",
                                "derived_seed_hex": seed.hex(),
                                "utf16_printable_ratio": f"{utf16_printable_ratio(dec2):.3f}",
                                "marker_shape": marker_shape(dec2),
                                **v2,
                            })
                for xor_offset in (0, 2, 4):
                    for preupdate in (False, True):
                        dec3 = public_xorpass(payload, key8, offset=xor_offset, include_prev=True, update_size_before=preupdate)
                        v3 = validate_plain(dec3, markers)
                        trial_rows.append({
                            "packet_no": pkt["packet_no"],
                            "tcp_stream": pkt["tcp_stream"],
                            "flow": pkt["flow"],
                            "direction": pkt["direction"],
                            "payload_len": len(payload),
                            "payload_hex": payload.hex(),
                            "key_name": key_name,
                            "key8_hex": key8.hex(),
                            "order_variant": f"XORpass_only_offset_{xor_offset}_preupdate_{int(preupdate)}",
                            "skip_bytes": "",
                            "length_field_mode": "not_applicable",
                            "block_bytes_decrypted": 0,
                            "tail_bytes_preserved": len(payload),
                            "provider": "pure_python",
                            "packet_9741_smkey_confirmed": "yes" if smkey_ok else "no",
                            "derived_seed_hex": seed.hex(),
                            "utf16_printable_ratio": f"{utf16_printable_ratio(dec3):.3f}",
                            "marker_shape": marker_shape(dec3),
                            **v3,
                        })
    write_csv(ART / "pass607_codex_startup_blowfish_trials.csv", trial_rows)
    matched = sorted({m for r in trial_rows for m in str(r.get("matched_messages", "")).split("|") if m})
    containment = sum(1 for r in trial_rows if r.get("utf16le_or_ascii_containment") == "yes")
    sane = sum(1 for r in trial_rows if r.get("length_sane") == "yes")
    comp = sum(1 for r in trial_rows if r.get("opcode_complement_ok") == "yes")
    summary = [
        "# Pass607 Codex Startup Blowfish Trial Summary",
        "",
        "- provider used: pure_python",
        f"- packet 9741 SM_KEY confirmed: {'yes' if smkey_ok else 'no'}",
        f"- derived seed: `{spaced_hex(seed)}`",
        f"- startup packets tested: {len(packets)}",
        f"- trial rows: {len(trial_rows)}",
        f"- length-sane rows: {sane}",
        f"- opcode complement rows: {comp}",
        f"- UTF-16LE/ASCII containment rows: {containment}",
        f"- matched known messages: {', '.join(matched) if matched else '(none)' }",
        "- no exact known plaintext was recovered from the PCAP.",
        "- no live process, client binary execution, memory dump, injection, or packet injection was used.",
    ]
    (ART / "pass607_codex_startup_blowfish_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(json.dumps({"smkey_ok": smkey_ok, "packets": len(packets), "rows": len(trial_rows), "matches": matched}, indent=2))


if __name__ == "__main__":
    main()
