#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def main() -> int:
    packets = parse_pcapng(PCAP)
    markers, _old, _total = load_current_markers()
    index_rows=[]; window_rows=[]
    for port, direction in ((7780,"S2C"),(10242,"S2C"),(10242,"C2S")):
        stream, ranges = build_stream_ranges(packets, port, direction)
        index_rows.append({"marker_index":"","marker_text":"","flow_role":flow_role(port),"server_port":port,"window_sec":"all","stream_direction":direction,"first_frame":ranges[0]["frame"] if ranges else "","last_frame":ranges[-1]["frame"] if ranges else "","packet_count":len(ranges),"total_payload_bytes":len(stream),"stream_offset_start":0,"stream_offset_end":len(stream),"largest_packet_len":max((r["len"] for r in ranges), default=0),"confidence":"high" if ranges else "low","reason":"full reassembled stream safe index; stream bytes not written"})
        for m in markers:
            for win in (10,):
                selected=[]
                for r in ranges:
                    if m["ts"] is not None and r["ts"] is not None and abs(r["ts"]-m["ts"])<=win:
                        selected.append(r)
                window_rows.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"flow_role":flow_role(port),"server_port":port,"window_sec":win,"stream_direction":direction,"first_frame":selected[0]["frame"] if selected else "","last_frame":selected[-1]["frame"] if selected else "","packet_count":len(selected),"total_payload_bytes":sum(r["len"] for r in selected),"stream_offset_start":selected[0]["start"] if selected else "","stream_offset_end":selected[-1]["end"] if selected else "","largest_packet_len":max((r["len"] for r in selected), default=0),"confidence":"high" if selected else "low","reason":"marker +/-10s stream window safe numeric metadata"})
    fields=["marker_index","marker_text","flow_role","server_port","window_sec","stream_direction","first_frame","last_frame","packet_count","total_payload_bytes","stream_offset_start","stream_offset_end","largest_packet_len","confidence","reason"]
    write_csv(ART/"pass651_stream_window_index.csv", index_rows, fields)
    write_csv(ART/"pass651_stream_marker_windows.csv", window_rows, fields)
    print({"stream_rows":len(index_rows),"window_rows":len(window_rows)})
    return 0
if __name__ == "__main__": raise SystemExit(main())
