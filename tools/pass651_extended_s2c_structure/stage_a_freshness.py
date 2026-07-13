#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    packets = parse_pcapng(PCAP)
    markers, old_count, total_log = load_current_markers()
    first_ts = min((p.ts for p in packets if p.ts is not None), default=None)
    last_ts = max((p.ts for p in packets if p.ts is not None), default=None)
    ports = Counter(p.server_port_guess for p in packets if p.server_port_guess)
    label = f"size={PCAP.stat().st_size if PCAP.exists() else 0};first={iso_time(first_ts)};last={iso_time(last_ts)}"
    rows = [
        {"item":"pcap_found","value":str(PCAP.exists()).lower(),"confidence":"high","reason":str(PCAP)},
        {"item":"pcap_size_bytes","value":PCAP.stat().st_size if PCAP.exists() else 0,"confidence":"high","reason":"filesystem size only; no hash used"},
        {"item":"first_packet_time","value":iso_time(first_ts),"confidence":"high","reason":"pcap timestamp metadata"},
        {"item":"last_packet_time","value":iso_time(last_ts),"confidence":"high","reason":"pcap timestamp metadata"},
        {"item":"detected_ports","value":";".join(f"{k}:{v}" for k,v in sorted(ports.items())) ,"confidence":"high","reason":"dynamic pcap metadata parser"},
        {"item":"current_capture_label","value":label,"confidence":"medium","reason":"label uses size + first_time + last_time only"},
        {"item":"old_s2c_oracle_rows_ignored","value":old_count,"confidence":"high","reason":"old rows ignored because S2C_A length ladder is present"},
        {"item":"s2c_a_rows_used","value":len(markers),"confidence":"high","reason":"current whisper length ladder markers only"},
        {"item":"log_rows_total","value":total_log,"confidence":"high","reason":"known plaintext log row count"},
    ]
    write_csv(ART/"pass651_stage_a_freshness.csv", rows, ["item","value","confidence","reason"])
    marker_rows=[]
    for m in markers:
        marker_rows.append({"item":f"marker_{m['marker_index']}","value":m["marker_text"],"confidence":"high","reason":f"len_ascii={m['marker_len_ascii']} time={m['logged_time']}"})
    write_csv(ART/"pass651_stage_a_marker_set.csv", marker_rows, ["item","value","confidence","reason"])
    print({"markers":len(markers),"old_ignored":old_count})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
