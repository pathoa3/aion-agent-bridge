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

SMKEY_PREFIX = bytes.fromhex("0b00f9015606fe")
SMKEY_MASKS = {
    "public_lobby_mask_ca667af68320a3": bytes.fromhex("ca667af68320a3"),
    "world_mask_f97b386199f45a": bytes.fromhex("f97b386199f45a"),
}
TAILS = {
    "tail_a16c5487": bytes.fromhex("a16c5487"),
    "tail_87546ca1": bytes.fromhex("87546ca1"),
    "tail_00000000": bytes.fromhex("00000000"),
    "tail_ffffffff": bytes.fromhex("ffffffff"),
}
FORMULA_PREFIXES = {
    "formula_c52beaa9": bytes.fromhex("c52beaa9"),
    "formula_a9ea2bc5": bytes.fromhex("a9ea2bc5"),
    "formula_309c8e23": bytes.fromhex("309c8e23"),
    "formula_238e9c30": bytes.fromhex("238e9c30"),
    "formula_4ff3f016": bytes.fromhex("4ff3f016"),
    "formula_16f0f34f": bytes.fromhex("16f0f34f"),
    "formula_bd6e2f07": bytes.fromhex("bd6e2f07"),
    "formula_072f6ebd": bytes.fromhex("072f6ebd"),
}
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
TRANSFORMS = ["Blowfish_only", "Blowfish_then_decXORPass", "decXORPass_then_Blowfish", "XORpass_only"]
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


def xor_repeat(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def derive_smkey(payload: bytes) -> list[dict[str, object]]:
    out = []
    if len(payload) != 11:
        return out
    for mask_label, mask in SMKEY_MASKS.items():
        decoded = xor_repeat(payload, mask)
        if decoded[:7] == SMKEY_PREFIX:
            out.append({
                "mask_label": mask_label,
                "seed": decoded[7:11],
                "prefix_ok": True,
            })
    return out


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


def apply_transform(payload: bytes, key: bytes, transform: str, offset: int) -> tuple[bytes, int, int]:
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
    return (
        (1000 if v["exact_utf16"] else 0)
        + (100 if v["ascii_secondary"] else 0)
        + (10 if v["length_sane"] else 0)
        + (5 if v["opcode_complement"] else 0)
        + float(v["utf16_ratio"])
    )


def local_trial_row(mode: str, candidate: str, update_rule: str, transform: str, offset: int, packet_no: int, v: dict[str, object], row_score: float, blocks: int, leftover: int) -> dict[str, object]:
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


def build_keys(seed_infos: list[dict[str, object]]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for i, info in enumerate(seed_infos):
        seed = info["seed"]
        assert isinstance(seed, bytes)
        for seed_label, prefix in {
            f"smkey{i}_{info['mask_label']}_seed": seed,
            f"smkey{i}_{info['mask_label']}_seed_reversed": seed[::-1],
        }.items():
            for tail_label, tail in TAILS.items():
                keys[f"{seed_label}+{tail_label}"] = prefix + tail
    for prefix_label, prefix in FORMULA_PREFIXES.items():
        for tail_label, tail in TAILS.items():
            keys[f"{prefix_label}+{tail_label}"] = prefix + tail
    return keys


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    rows = tcp_payload_rows(CAPTURE)
    by_packet = {int(r["packet_no"]): r for r in rows}
    target_rows = [by_packet[p] for p in TARGET_PACKETS if p in by_packet]
    target_packets_found = len(target_rows) == len(TARGET_PACKETS)
    main_flow = target_rows[0]["flow"] if target_rows else ""
    target_alignment_rows = []
    for packet_no, msg in TARGETS:
        r = by_packet.get(packet_no)
        utf16_len = len(msg.encode("utf-16le"))
        expected_len = utf16_len + 10
        target_alignment_rows.append({
            "packet_no": packet_no,
            "message": msg,
            "found": "yes" if r else "no",
            "direction": r["direction"] if r else "",
            "payload_len": r["payload_len"] if r else "",
            "expected_utf16_plus_10": expected_len,
            "length_delta": int(r["payload_len"]) - expected_len if r else "",
            "flow": r["flow"] if r else "",
        })
    smkey_candidates = []
    if main_flow:
        for r in rows:
            pno = int(r["packet_no"])
            if r["flow"] != main_flow or r["direction"] != "S2C" or pno >= TARGET_PACKETS[0] or int(r["payload_len"]) != 11:
                continue
            for info in derive_smkey(r["payload"]):
                info = dict(info)
                info["packet_no"] = pno
                smkey_candidates.append(info)
    smkey_before_found = bool(smkey_candidates)
    relevant_smkey = max(smkey_candidates, key=lambda x: int(x["packet_no"])) if smkey_candidates else None
    keys = build_keys([relevant_smkey] if relevant_smkey else [])
    direct_rows: list[dict[str, object]] = []
    matched: set[str] = set()
    exact_any = False
    best = {"score": -1.0, "candidate": "", "transform": "", "update_rule": "direct", "offset": 0}

    def consider(row: dict[str, object], v: dict[str, object], row_score: float) -> None:
        nonlocal exact_any, best
        matched.update(v["matched_utf16"])
        if v["exact_utf16"]:
            exact_any = True
        if row_score > float(best["score"]):
            best = {
                "score": row_score,
                "candidate": str(row["candidate_label"]),
                "transform": f"{row['transform']} offset={row['offset']}",
                "update_rule": str(row["update_rule"]),
            }

    if target_packets_found and keys:
        for candidate_label, key in keys.items():
            for transform_name in TRANSFORMS:
                for offset in OFFSETS:
                    for packet_no, msg in TARGETS:
                        pkt = by_packet[packet_no]
                        decoded, blocks, leftover = apply_transform(pkt["payload"], key, transform_name, offset)
                        v = validate(decoded, msg)
                        row_score = score(v)
                        row = local_trial_row("direct", candidate_label, "direct", transform_name, offset, packet_no, v, row_score, blocks, leftover)
                        direct_rows.append(row)
                        consider(row, v, row_score)
    direct_success = exact_any
    sequential_tested = False
    seq_rows: list[dict[str, object]] = []
    intermediate_count = 0
    if target_packets_found and keys and not direct_success and relevant_smkey:
        smkey_packet_no = int(relevant_smkey["packet_no"])
        c2s_stream = [
            r for r in rows
            if r["flow"] == main_flow and r["direction"] == "C2S" and smkey_packet_no < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0
        ]
        full_stream = [
            r for r in rows
            if r["flow"] == main_flow and smkey_packet_no < int(r["packet_no"]) <= max(TARGET_PACKETS) and int(r["payload_len"]) > 0
        ]
        intermediate_count = len([r for r in c2s_stream if int(r["packet_no"]) < TARGET_PACKETS[0]])
        sequential_tested = True
        for candidate_label, start_key in keys.items():
            for transform_name in TRANSFORMS:
                for offset in OFFSETS:
                    for update_rule in UPDATE_RULES:
                        state = key_to_u64(start_key)
                        stream = full_stream if update_rule == "H" else c2s_stream
                        counter = 0
                        for pkt in stream:
                            packet_no = int(pkt["packet_no"])
                            if pkt["direction"] == "C2S":
                                counter += 1
                            key = u64_to_key(state)
                            decoded, blocks, leftover = apply_transform(pkt["payload"], key, transform_name, offset)
                            if packet_no in dict(TARGETS):
                                msg = dict(TARGETS)[packet_no]
                                v = validate(decoded, msg)
                                row_score = score(v)
                                row = local_trial_row("sequential", candidate_label, update_rule, transform_name, offset, packet_no, v, row_score, blocks, leftover)
                                seq_rows.append(row)
                                consider(row, v, row_score)
                            state = update_state(state, update_rule, counter, pkt["payload"], decoded) & 0xFFFFFFFFFFFFFFFF

    all_local_rows = direct_rows + seq_rows
    write_csv(LOCAL_OUT / "kxseq_packet_alignment_local.csv", target_alignment_rows)
    write_csv(LOCAL_OUT / "kxseq_trials_full_local.csv", all_local_rows)
    debug_notes = [
        "# Pass608 KXSEQ Local Debug Notes",
        "",
        "Detailed output is local-only and not committed.",
        f"- target packets found: {target_packets_found}",
        f"- relevant SM_KEY found: {smkey_before_found}",
        f"- relevant SM_KEY packet label: {relevant_smkey['packet_no'] if relevant_smkey else '(none)'}",
        f"- candidate keys tested: {len(keys)}",
        f"- Blowfish provider: {BLOWFISH_PROVIDER}",
        f"- direct trial rows: {len(direct_rows)}",
        f"- sequential state tested: {sequential_tested}",
        f"- intermediate C2S packets before first message: {intermediate_count}",
        f"- sequential trial rows: {len(seq_rows)}",
        f"- exact UTF-16LE matches: {sum(1 for r in all_local_rows if r['exact_utf16'] == 'yes')}",
        f"- matched labels: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best candidate label: {best['candidate']}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best score: {float(best['score']):.3f}",
        "- no raw payload hex, hashes, or decoded byte blobs are written to Git artifacts.",
    ]
    (LOCAL_OUT / "kxseq_debug_notes_local.md").write_text("\n".join(debug_notes) + "\n", encoding="utf-8")

    decoder_success = exact_any
    decision = {
        "worker": "codex",
        "phase": "pass608_kxseq_startup_capture",
        "capture": "startup_world_open_kxseq",
        "blowfish_provider": BLOWFISH_PROVIDER,
        "known_messages_count": len(TARGETS),
        "target_packets_found": target_packets_found,
        "smkey_before_first_message_found": smkey_before_found,
        "intermediate_c2s_packets_before_first_message_count": intermediate_count,
        "direct_seed_tested": bool(direct_rows),
        "sequential_state_tested": sequential_tested,
        "update_rules_tested": UPDATE_RULES,
        "offsets_tested": OFFSETS,
        "trial_rows_local_only": len(all_local_rows),
        "decoder_success": bool(decoder_success),
        "exact_plaintext_recovered": bool(decoder_success),
        "matched_messages_count": len(matched),
        "matched_messages_labels": sorted(matched),
        "best_candidate_label": best["candidate"],
        "best_update_rule": best["update_rule"],
        "best_transform": best["transform"],
        "best_score": round(float(best["score"]), 3),
        "raw_payload_committed": False,
        "payload_hash_committed": False,
        "forbidden_methods_used": False,
        "reason": ("Exact KXSEQ plaintext recovered from PCAP." if decoder_success else f"KXSEQ targets were found and {len(all_local_rows)} local-only direct/sequential rows were tested, but no exact UTF-16LE KXSEQ plaintext was recovered."),
        "next_action": "Provide file-backed code/decompile/source evidence for the custom world-open game-channel transform, key update, or framing variant. Do not use memory dumps, attach/debug, live process, injection, anti-cheat bypass, or packet injection.",
    }
    (ART / "pass608_codex_kxseq_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    summary = [
        "# Pass608 Codex KXSEQ Startup Capture Summary",
        "",
        "- Git-safe summary only; detailed alignment and trials are local-only.",
        "- raw payload committed: false",
        "- payload hash committed: false",
        f"- known messages: {len(TARGETS)}",
        f"- target packets found: {'yes' if target_packets_found else 'no'}",
        f"- SM_KEY before first message found: {'yes' if smkey_before_found else 'no'}",
        f"- intermediate C2S packets before KXSEQ_001: {intermediate_count}",
        f"- direct seed tested: {'yes' if direct_rows else 'no'}",
        f"- sequential state tested: {'yes' if sequential_tested else 'no'}",
        f"- update rules tested: {', '.join(UPDATE_RULES)}",
        f"- offsets tested: {', '.join(str(o) for o in OFFSETS)}",
        f"- local-only trial rows: {len(all_local_rows)}",
        f"- Blowfish provider: {BLOWFISH_PROVIDER}",
        f"- exact UTF-16LE KXSEQ matches: {sum(1 for r in all_local_rows if r['exact_utf16'] == 'yes')}",
        f"- repeated KXSEQ_010_REPEAT matches: {sum(1 for r in all_local_rows if 'KXSEQ_010_REPEAT' in r['matched_utf16_labels'].split('|')) if all_local_rows else 0}",
        f"- matched message labels: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best candidate label: {best['candidate']}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best score: {float(best['score']):.3f}",
    ]
    (ART / "pass608_codex_kxseq_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    report = [
        "# Codex Pass608 KXSEQ Startup Capture Report",
        "",
        f"Decision: `{'decoder_success' if decoder_success else 'blocked_kxseq_no_plaintext_recovery'}`",
        "",
        f"- KXSEQ target packets found: {'yes' if target_packets_found else 'no'}",
        f"- intermediate C2S packets before KXSEQ_001: {intermediate_count}",
        f"- direct seed worked: {'yes' if decoder_success and not sequential_tested else 'no'}",
        f"- sequential state tested: {'yes' if sequential_tested else 'no'}",
        f"- exact KXSEQ plaintext recovered: {'yes' if decoder_success else 'no'}",
        f"- matched messages: {', '.join(sorted(matched)) if matched else '(none)'}",
        f"- best update rule: {best['update_rule']}",
        f"- best transform: {best['transform']}",
        f"- best candidate label: {best['candidate']}",
        f"- detailed outputs stayed local-only: yes",
        f"- Git contains no raw payload/hash/decrypted data: yes",
        "",
        "No forbidden methods were used. Next action is file-backed code/decompile/source evidence for the custom world-open game-channel transform, key update, or framing variant. Memory dumps are not recommended.",
    ]
    INBOX.mkdir(parents=True, exist_ok=True)
    (INBOX / "codex_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    if decoder_success:
        out = PRIVATE / "outbox"
        out.mkdir(parents=True, exist_ok=True)
        (out / "decoded_cleartext.txt").write_text("\n".join(sorted(matched)) + "\n", encoding="utf-8")
        (out / "decoder_success.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

