#!/usr/bin/env python3
from __future__ import annotations
from pass651_common import *


def window_stream(packets, marker, port, direction, win):
    selected=local_window_packets(packets, marker, port, direction, win)
    selected.sort(key=lambda p:(p.ts or 0,p.frame))
    chunks=[]; ranges=[]; off=0
    for p in selected:
        chunks.append(p.payload); ranges.append((off, off+p.payload_len, p.frame)); off+=p.payload_len
    return b"".join(chunks), ranges


def spans_packets(ranges, off, length):
    touched=[r for r in ranges if not (r[1] <= off or r[0] >= off+length)]
    return len(touched)>1, len(touched)


def main() -> int:
    packets=parse_pcapng(PCAP); markers,_old,_total=load_current_markers(); rows=[]; sigs=defaultdict(set); seq=0
    for m in markers:
        for port,direction in ((7780,"S2C"),(10242,"S2C"),(10242,"C2S")):
            for win in (3,10):
                stream,ranges=window_stream(packets,m,port,direction,win)
                if len(stream)<8: continue
                hits=[]
                for variant,crib in crib_variants(m["marker_text"]):
                    if len(crib)>len(stream): continue
                    step=1 if variant=="ascii_marker" else 2
                    for off in range(1, max(1,len(stream)-len(crib)+1), step):
                        slots,conflicts,sig=derive_slots(stream,off,crib)
                        if slots>=8 and conflicts==0:
                            sp,pc=spans_packets(ranges,off,len(crib))
                            score=min(100,40+len(crib)//2+(20 if sp else 0))
                            hits.append((score,variant,off,slots,conflicts,sig,sp,pc))
                hits.sort(key=lambda x:(x[0],x[3],x[6]), reverse=True)
                for score,variant,off,slots,conflicts,sig,sp,pc in hits[:25]:
                    seq+=1; cid=f"pass651_seq_{seq:05d}"; sigs[(m["marker_text"],port,direction)].add(f"{variant}|{off}|{sig}")
                    rows.append({"candidate_id":cid,"marker_text":m["marker_text"],"flow_role":flow_role(port),"server_port":port,"stream_direction":direction,"window_sec":win,"crib_variant":variant,"stream_relative_offset":off,"spans_packets":str(sp).lower(),"packet_count":pc,"slots_recovered":slots,"conflict_slots":conflicts,"all_8_covered":str(slots==8).lower(),"repeat_consistency":"pending","structural_score":score,"confidence":"medium_candidate","reason":"stream-window crib slot consistency only; key bytes and decoded text not written"})
    counts=Counter((m["marker_text"]) for m in markers)
    for r in rows:
        key=(r["marker_text"], int(r["server_port"]), r["stream_direction"])
        r["repeat_consistency"]="consistent" if counts[r["marker_text"]]>=2 and len(sigs[key])==1 else "not_consistent" if counts[r["marker_text"]]>=2 else "not_repeated"
    fields=["candidate_id","marker_text","flow_role","server_port","stream_direction","window_sec","crib_variant","stream_relative_offset","spans_packets","packet_count","slots_recovered","conflict_slots","all_8_covered","repeat_consistency","structural_score","confidence","reason"]
    write_csv(ART/"pass651_sequence_crib_candidates.csv", rows, fields)
    val=[]
    for r in rows:
        val.append({"candidate_id":r["candidate_id"],"markers_supported":1,"repeat_markers_validated":str(r["repeat_consistency"]=="consistent").lower(),"exact_marker_recovered":"false","s2c_keyroll_validated":"false","s2c_decoder_success":"false","confidence":"medium_hypothesis" if r["all_8_covered"]=="true" else "low","reason":"candidate not independently exact-decoded or keyroll-validated"})
    vfields=["candidate_id","markers_supported","repeat_markers_validated","exact_marker_recovered","s2c_keyroll_validated","s2c_decoder_success","confidence","reason"]
    write_csv(ART/"pass651_sequence_crib_validation.csv", val, vfields)
    print({"sequence_candidates":len(rows)})
    return 0
if __name__ == "__main__": raise SystemExit(main())
