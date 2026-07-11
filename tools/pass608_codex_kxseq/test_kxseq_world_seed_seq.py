from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

BRIDGE = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
PASS607_TOOLS = BRIDGE / "tools" / "pass607_codex_startup"
sys.path.insert(0, str(PASS607_TOOLS))

from pass607_codex_startup_common import spaced_hex, tcp_payload_rows, public_xorpass  # noqa: E402
try:  # noqa: E402
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.decrepit.ciphers import algorithms
    BLOWFISH_PROVIDER = "cryptography"
except Exception:  # noqa: E402
    Cipher = None
    modes = None
    algorithms = None
    from blowfish_pure import Blowfish
    BLOWFISH_PROVIDER = "pure_python"

CAPTURE = PRIVATE / "inbox" / "captures" / "startup_world_open_kxseq.pcapng"
LOCAL_OUT = PRIVATE / "outbox" / "pass608_kxseq_local"
ART = BRIDGE / "artifacts"
INBOX = BRIDGE / "inbox"

LOBBY_SMKEY_FRAME = 4094
WORLD_SMKEY_FRAME = 4119
FIRST_MESSAGE_FRAME = 4329
LOBBY_SEED = bytes.fromhex("191a7623")
WORLD_SEED = bytes.fromhex("2d66bd65")
TARGETS = [
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
TARGET_PACKETS = [p for p, _m in TARGETS]
TARGET_MESSAGES = [m for _p, m in TARGETS]
DIRECT_KEYS = {
    "world_seed_tail_a16c5487": bytes.fromhex("2d66bd65a16c5487"),
    "world_seed_rev_tail_a16c5487": bytes.fromhex("65bd662da16c5487"),
    "world_seed_tail_87546ca1": bytes.fromhex("2d66bd6587546ca1"),
    "world_seed_rev_tail_87546ca1": bytes.fromhex("65bd662d87546ca1"),
    "world_seed_tail_00000000": bytes.fromhex("2d66bd6500000000"),
    "world_seed_tail_ffffffff": bytes.fromhex("2d66bd65ffffffff"),
    "negative_lobby_seed_tail_a16c5487": bytes.fromhex("191a7623a16c5487"),
    "negative_lobby_seed_rev_tail_a16c5487": bytes.fromhex("23761a19a16c5487"),
}
SEQ_KEYS = {k: v for k, v in DIRECT_KEYS.items() if k.startswith("world_")}
TRANSFORMS = ["Blowfish_then_decXORPass", "decXORPass_then_Blowfish", "Blowfish_only", "XORpass_only"]
OFFSETS = [0, 2, 4, 6, 8]
UPDATE_RULES = ["A", "B", "C", "D", "E", "F", "G", "H"]


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else ["status"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def key_to_u64(key: bytes) -> int:
    return int.from_bytes(key, "little")


def u64_to_key(value: int) -> bytes:
    return (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def bf_region(payload: bytes, key: bytes, offset: int) -> tuple[bytes, int, int]:
    if offset >= len(payload):
        return payload, 0, max(0, len(payload) - offset)
    block_len = ((len(payload) - offset) // 8) * 8
    leftover = len(payload) - offset - block_len
    if block_len <= 0:
        return payload, 0, leftover
    chunk = payload[offset:offset + block_len]
    if BLOWFISH_PROVIDER == "cryptography":
        decryptor = Cipher(algorithms.Blowfish(key), modes.ECB()).decryptor()
        mid = decryptor.update(chunk) + decryptor.finalize()
    else:
        mid = Blowfish(key).decrypt_ecb(chunk)
    return payload[:offset] + mid + payload[offset + block_len:], block_len, leftover


def transform_payload(payload: bytes, key: bytes, transform: str, offset: int) -> tuple[bytes, int, int]:
    if transform == "Blowfish_only":
        return bf_region(payload, key, offset)
    if transform == "XORpass_only":
        return public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False), 0, len(payload)
    if transform == "Blowfish_then_decXORPass":
        bf, blocks, leftover = bf_region(payload, key, offset)
        return public_xorpass(bf, key, offset=offset, include_prev=True, update_size_before=False), blocks, leftover
    if transform == "decXORPass_then_Blowfish":
        x = public_xorpass(payload, key, offset=offset, include_prev=True, update_size_before=False)
        return bf_region(x, key, offset)
    raise ValueError(transform)


def first_dword(data: bytes) -> int:
    return int.from_bytes(data[:4], "little") if len(data) >= 4 else 0


def last_dword(data: bytes) -> int:
    return int.from_bytes(data[-4:], "little") if len(data) >= 4 else 0


def update_state(state: int, rule: str, counter: int, ciphertext: bytes, decoded: bytes) -> int:
    if rule == "A":
        return state + first_dword(decoded)
    if rule == "B":
        return state + last_dword(decoded)
    if rule == "C":
        return state + first_dword(ciphertext)
    if rule == "D":
        return state + last_dword(ciphertext)
    if rule == "E":
        return state + len(ciphertext) + first_dword(decoded)
    if rule == "F":
        return state + counter
    if rule == "G":
        return state
    if rule == "H":
        return state + len(ciphertext) + first_dword(decoded)
    raise ValueError(rule)


def utf16_ratio(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    even = data[:len(data) - (len(data) % 2)]
    text = even.decode("utf-16le", errors="ignore")
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable()) / len(text)


def validate(decoded: bytes, expected: str) -> dict[str, object]:
    matched_utf16 = [m for m in TARGET_MESSAGES if m.encode("utf-16le") in decoded]
    matched_ascii = [m for m in TARGET_MESSAGES if m.encode("ascii") in decoded]
    length_le = int.from_bytes(decoded[:2], "little") if len(decoded) >= 2 else -1
    length_sane = 2 <= length_le <= len(decoded) + 32
    complement = False
    for a, b in ((2, 3), (3, 4), (4, 5)):
        if len(decoded) > b and decoded[a] == ((~decoded[b]) & 0xFF):
            complement = True
    return {
        "exact_utf16": expected.encode("utf-16le") in decoded,
        "ascii_secondary": expected.encode("ascii") in decoded,
        "matched_utf16": matched_utf16,
        "matched_ascii": matched_ascii,
        "utf16_ratio": utf16_ratio(decoded),
        "length_sane": length_sane,
        "opcode_complement": complement,
    }


def score(v: dict[str, object]) -> float:
    return (1000 if v["exact_utf16"] else 0) + (100 if v["ascii_secondary"] else 0) + (10 if v["length_sane"] else 0) + (5 if v["opcode_complement"] else 0) + float(v["utf16_ratio"])


def local_row(mode: str, candidate: str, update_rule: str, transform: str, offset: int, packet_no: int, v: dict[str, object], row_score: float, blocks: int, leftover: int) -> dict[str, object]:
    return {
        "mode": mode,
        "candidate_label": candidate,
        "update_rule": update_rule,
        "transform": transform,
        "offset": offset,
        "packet_no": packet_no,
        "block_bytes_decrypted": blocks,
        "leftover_bytes": leftover,
        "exact_utf16": "yes" if v["exact_utf16"] else "no",
        "ascii_secondary": "yes" if v["ascii_secondary"] else "no",
        "matched_utf16_labels": "|".join(v["matched_utf16"]),
        "matched_ascii_labels": "|".join(v["matched_ascii"]),
        "utf16_printable_ratio": f"{float(v['utf16_ratio']):.3f}",
        "length_sane": "yes" if v["length_sane"] else "no",
        "opcode_complement": "yes" if v["opcode_complement"] else "no",
        "score": f"{row_score:.3f}",
    }


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    rows = tcp_payload_rows(CAPTURE)
    by_packet = {int(r["packet_no"]): r for r in rows}
    target_packets_found = all(p in by_packet for p in TARGET_PACKETS)
    world_frame_found = WORLD_SMKEY_FRAME in by_packet
    main_flow = by_packet[WORLD_SMKEY_FRAME]["flow"] if world_frame_found else (by_packet[TARGET_PACKETS[0]]["flow"] if target_packets_found else "")
    target_rows = [by_packet[p] for p in TARGET_PACKETS if p in by_packet]
    direct_rows: list[dict[str, object]] = []
    seq_rows: list[dict[str, object]] = []
    matched: set[str] = set()
    exact_any = False
    best = {"score": -1.0, "candidate": "", "update_rule": "", "transform": ""}

    def consider(row: dict[str, object], v: dict[str, object], row_score: float) -> None:
        nonlocal exact_any, best
        matched.update(v["matched_utf16"])
        if v["exact_utf16"]:
            exact_any = True
        if row_score > float(best["score"]):
            best = {"score": row_score, "candidate": str(row["candidate_label"]), "update_rule": str(row["update_rule"]), "transform": f"{row['transform']} offset={row['offset']}"}

    if target_packets_found:
        for candidate_label, key in DIRECT_KEYS.items():
            for transform in TRANSFORMS:
                for offset in OFFSETS:
                    for packet_no, msg in TARGETS:
                        pkt = by_packet[packet_no]
                        decoded, blocks, leftover = transform_payload(pkt["payload"], key, transform, offset)
                        v = validate(decoded, msg)
                        row_score = score(v)
                        row = local_row("direct", candidate_label, "direct", transform, offset, packet_no, v, row_score, blocks, leftover)
                        direct_rows.append(row)
                        consider(row, v, row_score)

    direct_success = exact_any
    c2s_stream = []
    full_stream = []
    intermediate_count = 0
    sequential_tested = False
    if target_packets_found and world_frame_found and not direct_success:
        c2s_stream = [r for r in rows if r["flow"] == main_flow and r["direction"] == "C2S" and WORLD_SMKEY_FRAME < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0]
        full_stream = [r for r in rows if r["flow"] == main_flow and WORLD_SMKEY_FRAME < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0]
        intermediate_count = len([r for r in c2s_stream if int(r["packet_no"]) < FIRST_MESSAGE_FRAME])
        sequential_tested = True
        for candidate_label, start_key in SEQ_KEYS.items():
            for transform in TRANSFORMS:
                for offset in OFFSETS:
                    for rule in UPDATE_RULES:
                        state = key_to_u64(start_key)
                        stream = full_stream if rule == "H" else c2s_stream
                        counter = 0
                        for pkt in stream:
                            packet_no = int(pkt["packet_no"])
                            if pkt["direction"] == "C2S":
                                counter += 1
                            key = u64_to_key(state)
                            decoded, blocks, leftover = transform_payload(pkt["payload"], key, transform, offset)
                            if packet_no in dict(TARGETS):
                                msg = dict(TARGETS)[packet_no]
                                v = validate(decoded, msg)
                                row_score = score(v)
                                row = local_row("sequential", candidate_label, rule, transform, offset, packet_no, v, row_score, blocks, leftover)
                                seq_rows.append(row)
                                consider(row, v, row_score)
                            state = update_state(state, rule, counter, pkt["payload"], decoded) & 0xFFFFFFFFFFFFFFFF

    all_rows = direct_rows + seq_rows
    write_csv(LOCAL_OUT / "kxseq_world_seed_seq_trials_full.csv", all_rows)
    notes = [
        "# Pass608 KXSEQ World Seed Sequential Debug Notes",
        "",
        "Detailed output is local-only and intentionally not committed.",
        f"- world SM_KEY frame found: {world_frame_found}",
        f"- world seed tested: {spaced_hex(WORLD_SEED)}",
        f"- target packets found: {target_packets_found}",
        f"- intermediate C2S packets between 4119 and 4329: {intermediate_count}",
        f"- direct rows: {len(direct_rows)}",
        f"- sequential rows: {len(seq_rows)}",
        f"- exact UTF-16LE matches: {sum(1 for r in all_rows if r['exact_utf16'] == 'yes')}",
        f"- matched labels: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best candidate: {best['candidate']}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best score: {float(best['score']):.3f}",
        "- no raw packet payload hex or decoded byte blobs are written to Git artifacts.",
    ]
    (LOCAL_OUT / "kxseq_world_seed_seq_debug_notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")

    decision = {
        "worker": "codex",
        "phase": "pass608_kxseq_world_seed_seq",
        "capture": "startup_world_open_kxseq",
        "known_messages_count": len(TARGETS),
        "target_packets_found": target_packets_found,
        "lobby_seed": spaced_hex(LOBBY_SEED),
        "world_seed": spaced_hex(WORLD_SEED),
        "world_smkey_frame": WORLD_SMKEY_FRAME,
        "first_message_frame": FIRST_MESSAGE_FRAME,
        "intermediate_c2s_packets_before_first_message_count": intermediate_count,
        "direct_world_seed_tested": bool(direct_rows),
        "sequential_state_tested": sequential_tested,
        "update_rules_tested": UPDATE_RULES,
        "offsets_tested": OFFSETS,
        "trial_rows_local_only": len(all_rows),
        "decoder_success": bool(exact_any),
        "exact_plaintext_recovered": bool(exact_any),
        "matched_messages_count": len(matched),
        "matched_messages_labels": sorted(matched),
        "best_candidate_label": best["candidate"],
        "best_update_rule": best["update_rule"],
        "best_transform": best["transform"],
        "best_score": round(float(best["score"]), 3),
        "raw_payload_committed": False,
        "payload_hash_committed": False,
        "forbidden_methods_used": False,
        "reason": ("Exact KXSEQ plaintext recovered from PCAP." if exact_any else f"World seed 2D 66 BD 65 was tested directly and with sequential mutation over {intermediate_count} intermediate C2S packets, but no exact UTF-16LE KXSEQ plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom world-open game-channel transform, key update, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass608_codex_kxseq_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass608 Codex KXSEQ World Seed Sequential Summary",
        "",
        "- Git-safe summary only; detailed trials are local-only.",
        "- raw payload committed: false",
        "- payload hash committed: false",
        f"- target packets found: {'yes' if target_packets_found else 'no'}",
        f"- lobby seed: `{spaced_hex(LOBBY_SEED)}`",
        f"- world seed tested: `{spaced_hex(WORLD_SEED)}`",
        f"- world SM_KEY frame: {WORLD_SMKEY_FRAME}",
        f"- first message frame: {FIRST_MESSAGE_FRAME}",
        f"- intermediate C2S packets before first message: {intermediate_count}",
        f"- direct world seed tested: {'yes' if direct_rows else 'no'}",
        f"- sequential state tested: {'yes' if sequential_tested else 'no'}",
        f"- update rules tested: {', '.join(UPDATE_RULES)}",
        f"- offsets tested: {', '.join(str(o) for o in OFFSETS)}",
        f"- local-only trial rows: {len(all_rows)}",
        f"- exact UTF-16LE KXSEQ matches: {sum(1 for r in all_rows if r['exact_utf16'] == 'yes')}",
        f"- matched message labels: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best candidate label: {best['candidate']}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best score: {float(best['score']):.3f}",
    ]
    (ART / "pass608_codex_kxseq_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass608 KXSEQ World Seed Sequential Report",
        "",
        f"Decision: `{'decoder_success' if exact_any else 'blocked_kxseq_world_seed_no_plaintext_recovery'}`",
        "",
        f"- frame 4119 world seed `2D 66 BD 65` tested: yes",
        f"- 15 intermediate C2S packets processed: {'yes' if intermediate_count == 15 else 'no'} ({intermediate_count})",
        f"- exact KXSEQ plaintext recovered: {'yes' if exact_any else 'no'}",
        f"- matched messages: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best candidate label: {best['candidate']}",
        "- detailed outputs stayed local-only: yes",
        "- Git contains no raw payload/hash/decrypted data: yes",
        "",
        "No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom world-open game-channel transform, key update, or framing variant. Memory dumps are not recommended.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    if exact_any:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(sorted(matched)) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
