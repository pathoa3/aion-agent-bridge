from __future__ import annotations

import json

from blowfish_pure import Blowfish, selftest_rows
from pass607_codex_startup_common import ART, INBOX, PRIVATE, STARTUP_PCAP, public_xorpass, spaced_hex, tcp_payload_rows, write_csv

TARGET_MESSAGES = {
    8745: "KXBOOT_SAY_01",
    8844: "KXBOOT_SAY_02_AAAAAAAAAAAAAAAA",
    8974: "KXBOOT_SAY_03_1234567890",
}
TARGET_PACKETS = [8745, 8844, 8974]
LOBBY_PACKET = 7522
WORLD_PACKET = 9741
LOBBY_SEED = bytes.fromhex("735a1208")
WORLD_SEED = bytes.fromhex("3990c5a2")
PREFIX_VARIANTS = {
    "lobby_735a1208": bytes.fromhex("735a1208"),
    "lobby_rev_08125a73": bytes.fromhex("08125a73"),
    "formula_c52beaa9": bytes.fromhex("c52beaa9"),
    "formula_a9ea2bc5": bytes.fromhex("a9ea2bc5"),
    "formula_309c8e23": bytes.fromhex("309c8e23"),
    "formula_238e9c30": bytes.fromhex("238e9c30"),
    "formula_4ff3f016": bytes.fromhex("4ff3f016"),
    "formula_16f0f34f": bytes.fromhex("16f0f34f"),
    "formula_bd6e2f07": bytes.fromhex("bd6e2f07"),
    "formula_072f6ebd": bytes.fromhex("072f6ebd"),
}
TAIL_VARIANTS = {
    "tail_a16c5487": bytes.fromhex("a16c5487"),
    "tail_87546ca1": bytes.fromhex("87546ca1"),
    "tail_00000000": bytes.fromhex("00000000"),
    "tail_ffffffff": bytes.fromhex("ffffffff"),
}
OFFSETS = [0, 2, 4, 6, 8]


def bf_decrypt_region(payload: bytes, key: bytes, offset: int) -> tuple[bytes, int, int]:
    if offset >= len(payload):
        return payload, 0, max(0, len(payload) - offset)
    block_len = ((len(payload) - offset) // 8) * 8
    leftover = len(payload) - offset - block_len
    if block_len <= 0:
        return payload, 0, leftover
    bf = Blowfish(key)
    mid = bf.decrypt_ecb(payload[offset:offset + block_len])
    return payload[:offset] + mid + payload[offset + block_len:], block_len, leftover


def utf16_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def header_hints(data: bytes) -> str:
    hints = []
    if len(data) >= 2:
        n = int.from_bytes(data[:2], "little")
        if n == len(data):
            hints.append("len_eq_payload")
        if 0 < n <= len(data) + 16:
            hints.append("len_plausible")
    if len(data) >= 4 and data[2] == ((~data[3]) & 0xFF):
        hints.append("comp_2_3")
    if len(data) >= 6 and data[4] == ((~data[5]) & 0xFF):
        hints.append("comp_4_5")
    if data.count(b"\x00") >= max(2, len(data) // 5):
        hints.append("nul_rich")
    return "|".join(hints)


def validate(decoded: bytes, expected: str, all_messages: list[str]) -> dict[str, object]:
    exact_utf16 = expected.encode("utf-16le") in decoded
    exact_ascii = expected.encode("ascii") in decoded
    matched_utf16 = [m for m in all_messages if m.encode("utf-16le") in decoded]
    matched_ascii = [m for m in all_messages if m.encode("ascii") in decoded]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = 2 <= length_le <= len(decoded) + 32
    comp_2_3 = len(decoded) > 3 and decoded[2] == ((~decoded[3]) & 0xFF)
    comp_3_4 = len(decoded) > 4 and decoded[3] == ((~decoded[4]) & 0xFF)
    comp_4_5 = len(decoded) > 5 and decoded[4] == ((~decoded[5]) & 0xFF)
    return {
        "exact_expected_utf16_containment": "yes" if exact_utf16 else "no",
        "exact_expected_ascii_containment_secondary": "yes" if exact_ascii else "no",
        "matched_utf16_messages": "|".join(matched_utf16),
        "matched_ascii_messages": "|".join(matched_ascii),
        "utf16_printable_ratio": f"{utf16_ratio(decoded):.3f}",
        "length_le": length_le,
        "length_sane": "yes" if length_sane else "no",
        "opcode_complement_2_3": "yes" if comp_2_3 else "no",
        "opcode_complement_3_4": "yes" if comp_3_4 else "no",
        "opcode_complement_4_5": "yes" if comp_4_5 else "no",
        "header_body_hints": header_hints(decoded),
        "decoded_prefix_hex": decoded[:96].hex(),
        "decoded_prefix_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in decoded[:96]),
    }


def score(row: dict[str, object]) -> tuple[int, int, int, float, int]:
    return (
        1000 if row["exact_expected_utf16_containment"] == "yes" else 0,
        100 if row["exact_expected_ascii_containment_secondary"] == "yes" else 0,
        10 if row["length_sane"] == "yes" else 0,
        float(row["utf16_printable_ratio"]),
        len(str(row["header_body_hints"]).split("|")) if row["header_body_hints"] else 0,
    )


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    self_rows = selftest_rows()
    self_ok = all(r["encrypt_ok"] == "yes" and r["decrypt_ok"] == "yes" and r["roundtrip_ok"] == "yes" for r in self_rows)
    rows = tcp_payload_rows(STARTUP_PCAP)
    by_packet = {int(r["packet_no"]): r for r in rows}
    required = [LOBBY_PACKET, *TARGET_PACKETS, WORLD_PACKET]
    missing = [p for p in required if p not in by_packet]
    if missing:
        raise SystemExit(f"missing required packets: {missing}")
    target_rows = [by_packet[p] for p in TARGET_PACKETS]
    all_messages = list(TARGET_MESSAGES.values())
    key_variants = [(f"{pn}+{tn}", prefix + tail) for pn, prefix in PREFIX_VARIANTS.items() for tn, tail in TAIL_VARIANTS.items()]
    trial_rows = []
    for pkt in target_rows:
        packet_no = int(pkt["packet_no"])
        payload = pkt["payload"]
        expected = TARGET_MESSAGES[packet_no]
        for key_name, key in key_variants:
            for offset in OFFSETS:
                bf, bf_blocks, bf_leftover = bf_decrypt_region(payload, key, offset)
                base = {
                    "packet_no": packet_no,
                    "direction": pkt["direction"],
                    "flow": pkt["flow"],
                    "payload_len": len(payload),
                    "payload_hex": payload.hex(),
                    "expected_message": expected,
                    "key_name": key_name,
                    "key_hex": key.hex(),
                    "transform": "Blowfish_only",
                    "offset": offset,
                    "length_field_mode": "included" if offset == 0 else f"first_{offset}_bytes_preserved",
                    "bf_full_block_bytes_decrypted": bf_blocks,
                    "leftover_bytes": bf_leftover,
                }
                base.update(validate(bf, expected, all_messages))
                trial_rows.append(base)

                x = public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False)
                xrow = dict(base)
                xrow.update({"transform": "decXORPass_only", "bf_full_block_bytes_decrypted": 0, "leftover_bytes": len(payload)})
                xrow.update(validate(x, expected, all_messages))
                trial_rows.append(xrow)

                bx = public_xorpass(bf, key, offset=offset, include_prev=True, update_size_before=False)
                bxrow = dict(base)
                bxrow.update({"transform": "Blowfish_then_decXORPass"})
                bxrow.update(validate(bx, expected, all_messages))
                trial_rows.append(bxrow)

                xb_mid = public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False)
                xb, xb_blocks, xb_leftover = bf_decrypt_region(xb_mid, key, offset)
                xbrow = dict(base)
                xbrow.update({"transform": "decXORPass_then_Blowfish", "bf_full_block_bytes_decrypted": xb_blocks, "leftover_bytes": xb_leftover})
                xbrow.update(validate(xb, expected, all_messages))
                trial_rows.append(xbrow)

    write_csv(ART / "pass607_codex_lobby_seed_blowfish_trials.csv", trial_rows)
    exact_rows = [r for r in trial_rows if r["exact_expected_utf16_containment"] == "yes"]
    matched = sorted({m for r in trial_rows for m in str(r.get("matched_utf16_messages", "")).split("|") if m})
    best = max(trial_rows, key=score) if trial_rows else {}
    best_evidence = (
        f"packet={best.get('packet_no')} key={best.get('key_name')} transform={best.get('transform')} offset={best.get('offset')} "
        f"utf16_ratio={best.get('utf16_printable_ratio')} length_sane={best.get('length_sane')} hints={best.get('header_body_hints')} "
        f"prefix_hex={best.get('decoded_prefix_hex')}"
        if best else ""
    )
    decision = {
        "worker": "codex",
        "phase": "pass607_lobby_seed_blowfish",
        "lobby_seed_tested": True,
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "target_packets": TARGET_PACKETS,
        "negative_control_world_seed": spaced_hex(WORLD_SEED),
        "blowfish_provider": "pure_python",
        "blowfish_selftest_passed": self_ok,
        "trial_rows": len(trial_rows),
        "decoder_success": bool(exact_rows),
        "exact_plaintext_recovered": bool(exact_rows),
        "matched_messages": matched,
        "best_candidate_key": f"{best.get('key_name', '')} / {best.get('key_hex', '')}",
        "best_candidate_transform": f"{best.get('transform', '')} offset={best.get('offset', '')}",
        "best_partial_evidence": best_evidence,
        "forbidden_methods_used": False,
        "reason": ("Exact UTF-16LE KXBOOT plaintext recovered from PCAP." if exact_rows else f"Pure-Python Blowfish self-tests passed and lobby seed 73 5A 12 08 was tested against packets 8745/8844/8974 with {len(trial_rows)} bounded rows, but no exact UTF-16LE KXBOOT plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom lobby/game-channel transform, key schedule, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass607_codex_lobby_seed_blowfish_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass607 Codex Lobby Seed Blowfish Summary",
        "",
        "- provider: pure_python",
        f"- Blowfish self-tests passed: {'yes' if self_ok else 'no'}",
        f"- lobby seed tested: `{spaced_hex(LOBBY_SEED)}`",
        f"- negative/phase-boundary world seed: `{spaced_hex(WORLD_SEED)}`",
        f"- lobby SM_KEY packet: {LOBBY_PACKET}",
        f"- target packets tested: {', '.join(str(p) for p in TARGET_PACKETS)}",
        f"- target packet directions: {', '.join(str(by_packet[p]['direction']) for p in TARGET_PACKETS)}",
        f"- target packet lengths: {', '.join(str(by_packet[p]['payload_len']) for p in TARGET_PACKETS)}",
        f"- key prefixes: {len(PREFIX_VARIANTS)}",
        f"- tail variants: {len(TAIL_VARIANTS)}",
        f"- offsets: {', '.join(str(o) for o in OFFSETS)}",
        f"- trial rows: {len(trial_rows)}",
        f"- exact UTF-16LE known plaintext matches: {len(exact_rows)}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best candidate key: {decision['best_candidate_key']}",
        f"- best candidate transform: {decision['best_candidate_transform']}",
        f"- best partial evidence: {best_evidence}",
        "- decoder_success is false unless exact known plaintext is recovered.",
        "",
        "## Packet Extraction",
    ]
    for p in required:
        r = by_packet[p]
        summary.append(f"- packet {p}: direction={r['direction']} flow={r['flow']} len={r['payload_len']} hex={r['payload'].hex()}")
    (ART / "pass607_codex_lobby_seed_blowfish_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass607 Lobby Seed Blowfish Report",
        "",
        f"Decision: `{'decoder_success' if decision['decoder_success'] else 'blocked_lobby_seed_no_plaintext_recovery'}`",
        "",
        "- Blowfish provider: `pure_python`",
        f"- Blowfish self-tests passed: {'yes' if self_ok else 'no'}",
        "- seed `73 5A 12 08` tested: yes",
        "- packets 8745, 8844, 8974 tested: yes",
        f"- exact KXBOOT plaintext recovered: {'yes' if exact_rows else 'no'}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best candidate: {decision['best_candidate_key']} with {decision['best_candidate_transform']}",
        f"- best partial evidence: {best_evidence}",
        "",
        "No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom lobby/game-channel transform, key schedule, or framing variant. Memory dumps are not recommended.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    if exact_rows:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(matched) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
