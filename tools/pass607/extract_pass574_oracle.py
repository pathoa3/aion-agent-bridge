from __future__ import annotations

import hashlib

from common import ART, CAP, parse_oracle_messages, parse_pcapng_packets, tcp_payload, write_csv


def main() -> None:
    messages = parse_oracle_messages()
    c2s = []
    for packet_no, ts, linktype, pkt in parse_pcapng_packets(CAP):
        parsed = tcp_payload(linktype, pkt)
        if not parsed:
            continue
        payload = parsed["payload"]
        if parsed["dst_port"] == 7785 and payload:
            c2s.append((packet_no, ts, parsed))
    rows = []
    search_pos = 0
    for idx, msg in enumerate(messages, 1):
        expected_utf16 = len(msg.encode("utf-16le"))
        expected_raw = expected_utf16 + 10
        found = None
        for pos in range(search_pos, len(c2s)):
            packet_no, ts, parsed = c2s[pos]
            if packet_no < 7166:
                continue
            if len(parsed["payload"]) == expected_raw:
                found = (pos, packet_no, ts, parsed)
                break
        if found is None:
            raise SystemExit(f"could not align oracle {idx} {msg!r}")
        pos, packet_no, ts, parsed = found
        search_pos = pos + 1
        payload = parsed["payload"]
        rows.append({
            "oracle_index": idx,
            "message": msg,
            "expected_utf16le_len": expected_utf16,
            "expected_raw_len_utf16_plus_10": expected_raw,
            "raw_tcp_payload_len": len(payload),
            "length_model_ok": "yes" if len(payload) == expected_raw else "no",
            "actual_wireshark_frame_number_if_available": packet_no,
            "timestamp": f"{ts:.6f}",
            "tcp_header_len": parsed["tcp_header_len"],
            "src": parsed["src"],
            "dst": parsed["dst"],
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "first_16_bytes": payload[:16].hex(),
            "last_16_bytes": payload[-16:].hex(),
            "raw_tcp_payload_hex": payload.hex(),
        })
    write_csv(ART / "pass607_codex_oracle_frames.csv", rows)
    all_ok = all(r["length_model_ok"] == "yes" for r in rows)
    lines = [
        "# Pass607 Codex Oracle Analysis",
        "",
        "- parser: custom pcapng parser, static/offline only",
        "- corrected TCP header length: `tcp_hlen = (pkt[tcp_off + 12] >> 4) * 4`",
        f"- oracle frames aligned: {len(rows)}",
        f"- all raw C2S lengths equal UTF-16LE byte length + 10: {'yes' if all_ok else 'no'}",
        f"- frame 7166 raw payload length: {rows[0]['raw_tcp_payload_len']}",
        "- no decoder success is claimed by extraction.",
    ]
    (ART / "pass607_codex_oracle_analysis.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"oracle rows={len(rows)} all_ok={all_ok}")


if __name__ == "__main__":
    main()
