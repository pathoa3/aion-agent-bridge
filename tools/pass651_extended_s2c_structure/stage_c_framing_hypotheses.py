#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def plaus_len(payload: bytes, header: str) -> bool:
    if header == "2byte_length" and len(payload) >= 2:
        n = int.from_bytes(payload[:2], "little")
        return n in (len(payload), len(payload)-2, len(payload)+2) or 0 < n < 4096
    if header == "4byte_length" and len(payload) >= 4:
        n = int.from_bytes(payload[:4], "little")
        return n in (len(payload), len(payload)-4, len(payload)+4) or 0 < n < 65536
    if header == "opcode_complement" and len(payload) >= 4:
        a = int.from_bytes(payload[:2], "little"); b = int.from_bytes(payload[2:4], "little")
        return ((a ^ b) & 0xffff) in (0xffff, 0x0000) or a < 0x4000
    if header == "batch_length_plausible":
        return 8 <= len(payload) <= 2048
    return bool(payload)


def main() -> int:
    packets = parse_pcapng(PCAP)
    markers, _old, _total = load_current_markers()
    rows=[]
    for port,direction in ((7780,"S2C"),(10242,"S2C"),(10242,"C2S")):
        for header in ("2byte_length","4byte_length","opcode_complement","batch_length_plausible","small_c2s_trigger_delayed_s2c"):
            for offset in (0,2,4,6,8,10,12,14,16):
                tested=0; plausible=0; per_marker=defaultdict(list)
                for m in markers:
                    for p in local_window_packets(packets,m,port,direction,10):
                        tested+=1
                        body=p.payload[offset:] if offset < len(p.payload) else b""
                        ok=plaus_len(body, header)
                        plausible += int(ok)
                        per_marker[m["marker_text"]].append(ok)
                repeats=[]
                for vals in per_marker.values():
                    if len(vals)>=2: repeats.append(len(set(vals))==1)
                repeat="true" if repeats and all(repeats) else "false" if repeats else "unknown"
                ratio=(plausible/tested) if tested else 0
                conf="high" if ratio>0.75 and repeat=="true" else "medium" if ratio>0.4 else "low"
                rows.append({"hypothesis_id":f"{port}_{direction}_{header}_off{offset}","flow_role":flow_role(port),"server_port":port,"direction":direction,"header_model":header,"body_offset_model":offset,"rows_tested":tested,"rows_plausible":plausible,"repeat_consistency":repeat,"marker_length_signal":"not_direct_length_ladder" if ratio<0.8 else "plausible_structure_only","confidence":conf,"reason":"safe framing plausibility checks on local payload windows; bytes not written"})
    fields=["hypothesis_id","flow_role","server_port","direction","header_model","body_offset_model","rows_tested","rows_plausible","repeat_consistency","marker_length_signal","confidence","reason"]
    write_csv(ART/"pass651_framing_hypotheses.csv", rows, fields)
    print({"hypotheses":len(rows)})
    return 0
if __name__ == "__main__": raise SystemExit(main())
