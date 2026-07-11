from __future__ import annotations

from pass607_codex_startup_common import ART, STARTUP_LOG, STARTUP_PCAP, parse_log_messages, public_xorpass, read_csv, tcp_payload_rows, validate_plain, write_csv


KEYS = {
    "seed_le_tail_le": bytes.fromhex("3990c5a2a16c5487"),
    "seed_be_tail_le": bytes.fromhex("a2c59039a16c5487"),
    "seed_le_tail_be": bytes.fromhex("3990c5a287546ca1"),
    "seed_be_tail_be": bytes.fromhex("a2c5903987546ca1"),
}


def main() -> None:
    verify = read_csv(ART / "pass607_codex_startup_packet9740_verify.csv")
    if not verify or not any(r.get("packet_exists") == "yes" for r in verify):
        raise SystemExit("packet 9740 verification did not produce rows")
    anchor = next((r for r in verify if r.get("row_type") == "matching_antigravity_ciphertext"), verify[0])
    flow = anchor["flow"]
    stream_id = anchor["tcp_stream"]
    anchor_packet = int(anchor["packet_no"])
    markers = parse_log_messages(STARTUP_LOG)
    if "KSTART_001" not in markers:
        markers.append("KSTART_001")
    packets = [
        r for r in tcp_payload_rows(STARTUP_PCAP)
        if r["flow"] == flow and int(r["packet_no"]) > anchor_packet and int(r["payload_len"]) > 0
    ]
    rows = []
    for p in packets[:400]:
        payload = p["payload"]
        for key_name, key8 in KEYS.items():
            for order in ["Blowfish_then_XORpass", "XORpass_then_Blowfish", "Blowfish_only"]:
                rows.append({
                    "packet_no": p["packet_no"],
                    "anchor_packet_no": anchor_packet,
                    "tcp_stream": stream_id,
                    "direction": p["direction"],
                    "payload_len": len(payload),
                    "payload_hex": payload.hex(),
                    "key_name": key_name,
                    "key8_hex": key8.hex(),
                    "order_variant": order,
                    "status": "not_run_blowfish_library_unavailable",
                    "length_le": "",
                    "length_sane": "",
                    "opcode_hex": "",
                    "opcode_complement_ok": "",
                    "utf16le_or_ascii_containment": "no",
                    "matched_messages": "",
                    "decoded_prefix_hex": "",
                    "decoded_prefix_ascii": "",
                    "notes": "No local Python Blowfish/Crypto/cryptography/openssl provider was available; no unknown binaries were run.",
                })
            for update_size in (False, True):
                for offset in (0, 2):
                    decoded = public_xorpass(payload, key8, offset=offset, include_prev=True, update_size_before=update_size)
                    v = validate_plain(decoded, markers)
                    row = {
                        "packet_no": p["packet_no"],
                        "anchor_packet_no": anchor_packet,
                        "tcp_stream": stream_id,
                        "direction": p["direction"],
                        "payload_len": len(payload),
                        "payload_hex": payload.hex(),
                        "key_name": key_name,
                        "key8_hex": key8.hex(),
                        "order_variant": f"XORpass_only_offset_{offset}_preupdate_{int(update_size)}",
                        "status": "tested",
                        "notes": "public staticKey XORpass only",
                    }
                    row.update(v)
                    rows.append(row)
    write_csv(ART / "pass607_codex_startup_key_trials.csv", rows)
    exact_or_partial = [r for r in rows if r.get("utf16le_or_ascii_containment") == "yes"]
    md = [
        "# Pass607 Codex Startup Key Trials",
        "",
        f"- anchor packet for candidate key: {anchor_packet}",
        f"- same-flow packets after anchor considered: {len(packets[:400])}",
        f"- candidate key8 values: {len(KEYS)}",
        f"- trial rows: {len(rows)}",
        f"- marker containment matches: {len(exact_or_partial)}",
        "- Blowfish-required variants were recorded as not run because no offline Blowfish provider is installed in this environment.",
        "- XORpass-only public-family variants were tested.",
        "- no exact plaintext recovery is claimed.",
    ]
    (ART / "pass607_codex_startup_key_trials.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"startup key trials={len(rows)} marker_matches={len(exact_or_partial)}")


if __name__ == "__main__":
    main()
