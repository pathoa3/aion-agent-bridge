from __future__ import annotations

import csv
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers import algorithms

from pass607_codex_startup_common import ART, INBOX, PRIVATE, STARTUP_LOG, STARTUP_PCAP, parse_log_messages, public_xorpass, spaced_hex, tcp_payload_rows, write_csv

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
SEED_VARIANTS = {
    "lobby_seed_le": bytes.fromhex("735a1208"),
    "lobby_seed_be": bytes.fromhex("08125a73"),
    "formula_c52beaa9": bytes.fromhex("c52beaa9"),
    "formula_a9ea2bc5": bytes.fromhex("a9ea2bc5"),
    "formula_309c8e23": bytes.fromhex("309c8e23"),
    "formula_238e9c30": bytes.fromhex("238e9c30"),
    "formula_4ff3f016": bytes.fromhex("4ff3f016"),
    "formula_16f0f34f": bytes.fromhex("16f0f34f"),
    "formula_bd6e2f07": bytes.fromhex("bd6e2f07"),
    "formula_072f6ebd": bytes.fromhex("072f6ebd"),
    "negative_world_seed_le": bytes.fromhex("3990c5a2"),
    "negative_world_seed_be": bytes.fromhex("a2c59039"),
}
TAIL_VARIANTS = {
    "tail_a16c5487": bytes.fromhex("a16c5487"),
    "tail_87546ca1": bytes.fromhex("87546ca1"),
    "tail_zero": bytes.fromhex("00000000"),
    "tail_ff": bytes.fromhex("ffffffff"),
}
SELFTEST = {
    "key": bytes.fromhex("0123456789abcdef"),
    "plaintext": bytes.fromhex("0123456789abcdef"),
    "ciphertext": bytes.fromhex("008a8314ee2b27a3"),
}


def bf_decrypt_blocks(key: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    dec = Cipher(algorithms.Blowfish(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def bf_encrypt_blocks(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.Blowfish(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def decrypt_region_bf(payload: bytes, key: bytes, offset: int) -> tuple[bytes, int, int]:
    if offset >= len(payload):
        return payload, 0, max(0, len(payload) - offset)
    block_len = ((len(payload) - offset) // 8) * 8
    leftover = len(payload) - offset - block_len
    if block_len <= 0:
        return payload, 0, leftover
    mid = bf_decrypt_blocks(key, payload[offset:offset + block_len])
    return payload[:offset] + mid + payload[offset + block_len:], block_len, leftover


def utf16_printable_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def validate(data: bytes, expected_msg: str, all_messages: list[str]) -> dict[str, object]:
    expected_utf16 = expected_msg.encode("utf-16le")
    matched_utf16 = [m for m in all_messages if m.encode("utf-16le") in data]
    matched_ascii = [m for m in all_messages if m.encode("ascii") in data]
    length_le = int.from_bytes(data[:2], "little") if len(data) >= 2 else -1
    length_sane = 2 <= length_le <= len(data) + 32
    comp_2_3 = len(data) > 3 and data[2] == ((~data[3]) & 0xFF)
    comp_3_4 = len(data) > 4 and data[3] == ((~data[4]) & 0xFF)
    comp_4_5 = len(data) > 5 and data[4] == ((~data[5]) & 0xFF)
    text = data.decode("utf-16le", errors="ignore")
    shape = []
    if "KXBOOT" in text:
        shape.append("kxboot_utf16_text")
    if "SAY" in text:
        shape.append("say_utf16_text")
    if data.count(b"\x00") >= max(2, len(data) // 5):
        shape.append("many_nuls")
    return {
        "exact_expected_utf16_containment": "yes" if expected_utf16 in data else "no",
        "utf16_containment": "yes" if matched_utf16 else "no",
        "ascii_containment": "yes" if matched_ascii else "no",
        "matched_utf16_messages": "|".join(matched_utf16),
        "matched_ascii_messages": "|".join(matched_ascii),
        "utf16_printable_ratio": f"{utf16_printable_ratio(data):.3f}",
        "length_le": length_le,
        "length_sane": "yes" if length_sane else "no",
        "opcode_complement_2_3": "yes" if comp_2_3 else "no",
        "opcode_complement_3_4": "yes" if comp_3_4 else "no",
        "opcode_complement_4_5": "yes" if comp_4_5 else "no",
        "marker_shape": "|".join(shape),
        "decoded_prefix_hex": data[:96].hex(),
        "decoded_prefix_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:96]),
    }


def run_selftest() -> tuple[bool, list[dict[str, object]]]:
    actual_cipher = bf_encrypt_blocks(SELFTEST["key"], SELFTEST["plaintext"])
    actual_plain = bf_decrypt_blocks(SELFTEST["key"], SELFTEST["ciphertext"])
    row = {
        "provider": "cryptography",
        "key_hex": SELFTEST["key"].hex(),
        "plaintext_hex": SELFTEST["plaintext"].hex(),
        "expected_ciphertext_hex": SELFTEST["ciphertext"].hex(),
        "actual_ciphertext_hex": actual_cipher.hex(),
        "actual_decrypted_plaintext_hex": actual_plain.hex(),
        "encrypt_ok": "yes" if actual_cipher == SELFTEST["ciphertext"] else "no",
        "decrypt_ok": "yes" if actual_plain == SELFTEST["plaintext"] else "no",
    }
    ok = row["encrypt_ok"] == "yes" and row["decrypt_ok"] == "yes"
    return ok, [row]


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    ok, self_rows = run_selftest()
    write_csv(ART / "pass607_codex_lobby_blowfish_selftest.csv", self_rows)
    (ART / "pass607_codex_lobby_blowfish_selftest.md").write_text(
        "# Pass607 Codex Lobby Blowfish Self-Test\n\n"
        "- provider: cryptography\n"
        "- vector key: `01 23 45 67 89 AB CD EF`\n"
        "- vector plaintext: `01 23 45 67 89 AB CD EF`\n"
        "- expected ciphertext: `00 8A 83 14 EE 2B 27 A3`\n"
        f"- self-test passed: {'yes' if ok else 'no'}\n",
        encoding="utf-8",
    )
    if not ok:
        raise SystemExit("Blowfish self-test failed")

    all_rows = tcp_payload_rows(STARTUP_PCAP)
    by_packet = {int(r["packet_no"]): r for r in all_rows}
    required = [LOBBY_PACKET, *TARGET_PACKETS, WORLD_PACKET]
    missing = [p for p in required if p not in by_packet]
    if missing:
        raise SystemExit(f"missing required packets: {missing}")
    lobby = by_packet[LOBBY_PACKET]
    world = by_packet[WORLD_PACKET]
    targets = [by_packet[p] for p in TARGET_PACKETS]
    known_messages = list(TARGET_MESSAGES.values())
    for msg in parse_log_messages(STARTUP_LOG):
        if msg not in known_messages:
            known_messages.append(msg)

    key_variants = []
    for seed_name, seed in SEED_VARIANTS.items():
        for tail_name, tail in TAIL_VARIANTS.items():
            key_variants.append((f"{seed_name}+{tail_name}", seed + tail, seed_name.startswith("negative_world")))

    trial_rows = []
    for pkt in targets:
        packet_no = int(pkt["packet_no"])
        payload = pkt["payload"]
        expected_msg = TARGET_MESSAGES[packet_no]
        for key_name, key, is_world_negative in key_variants:
            for offset in (0, 2, 4):
                bf, bf_blocks, bf_leftover = decrypt_region_bf(payload, key, offset)
                v = validate(bf, expected_msg, known_messages)
                trial_rows.append({
                    "packet_no": packet_no,
                    "direction": pkt["direction"],
                    "flow": pkt["flow"],
                    "payload_len": len(payload),
                    "payload_hex": payload.hex(),
                    "expected_message": expected_msg,
                    "key_name": key_name,
                    "key_hex": key.hex(),
                    "is_later_world_seed_negative_control": "yes" if is_world_negative else "no",
                    "transform": "Blowfish_ECB_only",
                    "offset": offset,
                    "length_field_mode": "included" if offset == 0 else f"first_{offset}_bytes_preserved",
                    "bf_full_block_bytes_decrypted": bf_blocks,
                    "leftover_bytes": bf_leftover,
                    **v,
                })
                for xor_offset in (0, 2, 4):
                    x_after_bf = public_xorpass(bf, key, offset=xor_offset, include_prev=True, update_size_before=False)
                    v2 = validate(x_after_bf, expected_msg, known_messages)
                    trial_rows.append({
                        "packet_no": packet_no,
                        "direction": pkt["direction"],
                        "flow": pkt["flow"],
                        "payload_len": len(payload),
                        "payload_hex": payload.hex(),
                        "expected_message": expected_msg,
                        "key_name": key_name,
                        "key_hex": key.hex(),
                        "is_later_world_seed_negative_control": "yes" if is_world_negative else "no",
                        "transform": f"Blowfish_ECB_then_decXORPass_xor_offset_{xor_offset}",
                        "offset": offset,
                        "length_field_mode": "included" if offset == 0 else f"first_{offset}_bytes_preserved",
                        "bf_full_block_bytes_decrypted": bf_blocks,
                        "leftover_bytes": bf_leftover,
                        **v2,
                    })
                    x_first = public_xorpass(payload, key, offset=xor_offset, include_prev=True, update_size_before=False)
                    xb, xb_blocks, xb_leftover = decrypt_region_bf(x_first, key, offset)
                    v3 = validate(xb, expected_msg, known_messages)
                    trial_rows.append({
                        "packet_no": packet_no,
                        "direction": pkt["direction"],
                        "flow": pkt["flow"],
                        "payload_len": len(payload),
                        "payload_hex": payload.hex(),
                        "expected_message": expected_msg,
                        "key_name": key_name,
                        "key_hex": key.hex(),
                        "is_later_world_seed_negative_control": "yes" if is_world_negative else "no",
                        "transform": f"decXORPass_then_Blowfish_ECB_xor_offset_{xor_offset}",
                        "offset": offset,
                        "length_field_mode": "included" if offset == 0 else f"first_{offset}_bytes_preserved",
                        "bf_full_block_bytes_decrypted": xb_blocks,
                        "leftover_bytes": xb_leftover,
                        **v3,
                    })
                    x_only = public_xorpass(payload, key, offset=xor_offset, include_prev=True, update_size_before=False)
                    v4 = validate(x_only, expected_msg, known_messages)
                    trial_rows.append({
                        "packet_no": packet_no,
                        "direction": pkt["direction"],
                        "flow": pkt["flow"],
                        "payload_len": len(payload),
                        "payload_hex": payload.hex(),
                        "expected_message": expected_msg,
                        "key_name": key_name,
                        "key_hex": key.hex(),
                        "is_later_world_seed_negative_control": "yes" if is_world_negative else "no",
                        "transform": f"decXORPass_only_xor_offset_{xor_offset}",
                        "offset": offset,
                        "length_field_mode": "not_applicable",
                        "bf_full_block_bytes_decrypted": 0,
                        "leftover_bytes": len(payload),
                        **v4,
                    })
    write_csv(ART / "pass607_codex_lobby_seed_trials.csv", trial_rows)

    exact_rows = [r for r in trial_rows if r["exact_expected_utf16_containment"] == "yes"]
    matched = sorted({m for r in trial_rows for m in str(r["matched_utf16_messages"]).split("|") if m})
    best = None
    def score(row: dict[str, object]) -> tuple[int, float, int, int]:
        return (
            100 if row["exact_expected_utf16_containment"] == "yes" else 0,
            float(row["utf16_printable_ratio"]),
            5 if row["length_sane"] == "yes" else 0,
            3 if row["opcode_complement_2_3"] == "yes" else 0,
        )
    if trial_rows:
        best = max(trial_rows, key=score)
    decision = {
        "worker": "codex",
        "phase": "pass607_lobby_seed_blowfish",
        "blowfish_provider": "cryptography",
        "blowfish_selftest_passed": ok,
        "lobby_smkey_packet": LOBBY_PACKET,
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "target_packets": TARGET_PACKETS,
        "tested_later_world_seed_as_negative_control": True,
        "decoder_success": bool(exact_rows),
        "exact_plaintext_recovered": bool(exact_rows),
        "matched_messages": matched,
        "best_candidate_key": best["key_name"] + " / " + best["key_hex"] if best else "",
        "best_candidate_transform": best["transform"] + f" offset={best['offset']}" if best else "",
        "packet_sink_found": False,
        "forbidden_methods_used": False,
        "reason": ("Exact known plaintext recovered from lobby-seed startup packets." if exact_rows else f"cryptography Blowfish self-test passed and packets 8745/8844/8974 were tested with {len(key_variants)} key variants and {len(trial_rows)} bounded transform rows, but no exact UTF-16LE KXBOOT plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom lobby/game-channel transform, key schedule, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass607_codex_lobby_seed_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass607 Codex Lobby Seed Blowfish Summary",
        "",
        "- provider: cryptography",
        f"- self-test passed: {'yes' if ok else 'no'}",
        f"- lobby SM_KEY packet: {LOBBY_PACKET}",
        f"- lobby packet direction: {lobby['direction']}",
        f"- lobby packet payload length: {lobby['payload_len']}",
        f"- later world SM_KEY packet negative control: {WORLD_PACKET}, payload length {world['payload_len']}",
        f"- target packets tested: {', '.join(str(p) for p in TARGET_PACKETS)}",
        f"- target packet directions: {', '.join(str(t['direction']) for t in targets)}",
        f"- key variants: {len(key_variants)}",
        f"- trial rows: {len(trial_rows)}",
        f"- exact UTF-16LE KXBOOT matches: {len(exact_rows)}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best candidate key: {decision['best_candidate_key']}",
        f"- best candidate transform: {decision['best_candidate_transform']}",
        "- packet_sink_found: false",
        "- decoder_success is false unless exact known plaintext is recovered.",
        "",
        "## Packet extraction",
    ]
    for p in required:
        r = by_packet[p]
        summary.append(f"- packet {p}: direction={r['direction']} flow={r['flow']} len={r['payload_len']} hex={r['payload'].hex()}")
    (ART / "pass607_codex_lobby_seed_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass607 Lobby Seed Blowfish Report",
        "",
        f"Decision: `{'decoder_success' if decision['decoder_success'] else 'blocked_lobby_seed_no_plaintext_recovery'}`",
        "",
        "- Blowfish provider: `cryptography`",
        f"- Blowfish self-test passed: {'yes' if ok else 'no'}",
        "- packet 7522 lobby SM_KEY source checked: yes",
        "- lobby seed: `73 5A 12 08`",
        "- later world seed `39 90 C5 A2` tested only as negative control: yes",
        "- packets 8745/8844/8974 tested: yes",
        f"- exact KXBOOT plaintext recovered: {'yes' if exact_rows else 'no'}",
        f"- matched messages: {', '.join(matched) if matched else '(none)'}",
        f"- best candidate: {decision['best_candidate_key']} with {decision['best_candidate_transform']}",
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
