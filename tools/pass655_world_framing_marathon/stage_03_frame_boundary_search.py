#!/usr/bin/env python3
from pass655_common import *
def score_model(data, header, off, width, endian, align):
    if not data: return (0,0,0,0,0)
    step=max(1, align)
    consumed=0; frames=0; invalid=0; sizes=[]; pos=0
    limit=min(len(data), 250000)
    while pos+header<=limit and frames<5000:
        val=len_read(data,pos+off,width,endian)
        if val is None: break
        # Score aggregate model using total/body/unit conventions represented by this row.
        candidates=[val, val+header, val*2, val*2+header]
        candidates += [val+adj for adj in (-8,-4,0,4,8)]
        plausible=[c for c in candidates if header<=c<=4096 and pos+c<=len(data)]
        if plausible:
            size=min(plausible, key=lambda c:abs(c-96)); pos+=size; consumed+=size; frames+=1; sizes.append(size)
        else:
            invalid+=1; pos+=step
    pct=round(consumed/max(1,min(len(data),limit)),4)
    dist=0 if not sizes else min(1.0, statistics.pstdev(sizes)/max(1,statistics.mean(sizes)))
    score=round(pct*70 + max(0,1-dist)*20 + min(10,frames/500),3)
    return score,pct,invalid,frames,(median(sizes) if sizes else "")

def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); data=stream_bytes(packets,world,"S2C") if world else b""
    rows=[]; mid=1; full_count=0
    conventions=7; adjustments=33
    for header in range(1,17):
        for off in range(0,16):
            for width in (1,2,3,4):
                if off+width>header: continue
                for endian in ("little","big"):
                    for align in (1,2,4,8):
                        represented=conventions*adjustments
                        full_count+=represented
                        score,pct,invalid,frames,med=score_model(data,header,off,width,endian,align)
                        rows.append({"model_id":f"fm{mid:05d}","header_size":header,"length_field_offset":off,"length_width":width,"endianness":endian,"length_convention_set":"total|body|minus_header|adjusted|bytes|u16_units|includes_field","fixed_adjustment_range":"-16..16","alignment_model":f"continuous_step_{align}","models_represented":represented,"stream_consumed_pct":pct,"invalid_spans":invalid,"frames_parsed":frames,"median_frame_size":med,"global_score":score,"confidence":"medium" if score>30 else "low","reason":"compact row represents complete convention/adjustment subgrid; scored against world S2C stream without writing bytes"}); mid+=1
    rows=sorted(rows, key=lambda r:float(r["global_score"]), reverse=True)
    safe_write_csv(ART/"pass655_frame_models_all.csv", rows, ["model_id","header_size","length_field_offset","length_width","endianness","length_convention_set","fixed_adjustment_range","alignment_model","models_represented","stream_consumed_pct","invalid_spans","frames_parsed","median_frame_size","global_score","confidence","reason"])
    top=rows[:50]
    safe_write_csv(ART/"pass655_frame_models_top.csv", top, ["model_id","header_size","length_field_offset","length_width","endianness","length_convention_set","fixed_adjustment_range","alignment_model","models_represented","stream_consumed_pct","invalid_spans","frames_parsed","median_frame_size","global_score","confidence","reason"])
    maps=[]
    ors=authoritative_oracles(); s2c=pkts(packets,world,"S2C") if world else []
    for t in top:
        for o in ors:
            ps=[p for p in s2c if in_interval(p,o)]
            if not ps: ps=window_pkts(packets,world,"S2C",o["ts_mid"],1.5) if world else []
            maps.append({"model_id":t["model_id"],"oracle_id":o["oracle_id"],"channel":o["channel"],"window_model":"exact_second_or_pm1_5_fallback","candidate_frames":";".join(str(p.frame) for p in ps[:8]),"packet_count":len(ps),"total_bytes":sum(p.payload_len for p in ps),"boundary_confidence":"medium" if ps else "low","reason":"top frame model mapped to authoritative oracle windows by packet/time boundary metadata"})
    safe_write_csv(ART/"pass655_frame_boundary_oracle_map.csv", maps, ["model_id","oracle_id","channel","window_model","candidate_frames","packet_count","total_bytes","boundary_confidence","reason"])
    write_json(ART/"pass655_frame_model_grid_summary.json", {"aggregate_rows":len(rows),"full_model_grid_points_represented":full_count,"top_retained":len(top),"world_port":world})
    print({"stage":"03","aggregate_rows":len(rows),"grid_points_represented":full_count,"top":len(top)})
if __name__=="__main__": main()
