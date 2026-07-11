from __future__ import annotations

from pass607_codex_startup_common import ART, PACKET9740_HEX, STARTUP_PCAP, spaced_hex, tcp_payload_rows, write_csv


def main() -> None:
    rows = []
    expected = bytes.fromhex(PACKET9740_HEX)
    payload_rows = tcp_payload_rows(STARTUP_PCAP)
    for r in payload_rows:
        if int(r["packet_no"]) != 9740:
            continue
        payload = r["payload"]
        rows.append({
            "row_type": "requested_packet_9740",
            "packet_no": r["packet_no"],
            "packet_exists": "yes",
            "tcp_stream": r["tcp_stream"],
            "flow": r["flow"],
            "direction": r["direction"],
            "src": r["src"],
            "dst": r["dst"],
            "seq": r["seq"],
            "ack": r["ack"],
            "tcp_header_len": r["tcp_header_len"],
            "raw_payload_length": len(payload),
            "raw_payload_hex": payload.hex(),
            "raw_payload_spaced_hex": spaced_hex(payload),
            "matches_antigravity_hex": "yes" if payload == expected else "no",
        })
    for r in payload_rows:
        payload = r["payload"]
        if payload == expected or expected in payload:
            rows.append({
                "row_type": "matching_antigravity_ciphertext",
                "packet_no": r["packet_no"],
                "packet_exists": "yes",
                "tcp_stream": r["tcp_stream"],
                "flow": r["flow"],
                "direction": r["direction"],
                "src": r["src"],
                "dst": r["dst"],
                "seq": r["seq"],
                "ack": r["ack"],
                "tcp_header_len": r["tcp_header_len"],
                "raw_payload_length": len(payload),
                "raw_payload_hex": payload.hex(),
                "raw_payload_spaced_hex": spaced_hex(payload),
                "matches_antigravity_hex": "yes",
            })
    if not rows:
        rows.append({
            "row_type": "requested_packet_9740",
            "packet_no": 9740,
            "packet_exists": "no",
            "tcp_stream": "",
            "flow": "",
            "direction": "",
            "src": "",
            "dst": "",
            "seq": "",
            "ack": "",
            "tcp_header_len": "",
            "raw_payload_length": "",
            "raw_payload_hex": "",
            "raw_payload_spaced_hex": "",
            "matches_antigravity_hex": "no",
        })
    write_csv(ART / "pass607_codex_startup_packet9740_verify.csv", rows)
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
