#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/"tools"/"pass655_world_framing_marathon"))
from pass655_common import parse_pcapng, detect_world_port, stream_bytes, len_read, PCAP
MODEL={'combined_model_id': 'cm011', 'frame_model_id': 'fm03614', 'header_size': '16', 'length_rule': 'off15_w1_big', 'message_type_field': '15', 'channel_field': 'candidate', 'body_start': '16', 'repeat_score': '0.625', 'channel_score': '1.0', 'parser_constraint_score': '0.875', 'negative_control_score': '0.5', 'total_score': '73.692', 'confidence': 'medium', 'reason': 'coherent model rank combining framing, field, repeat, channel, and existing parser constraints'}
def split(data):
    header=int(MODEL["header_size"])
    parts=MODEL["length_rule"].split("_")
    off=int(parts[0][3:]); width=int(parts[1][1:]); endian=parts[2]
    pos=0; out=[]
    while pos+header<=len(data) and len(out)<10000:
        val=len_read(data,pos+off,width,endian)
        cands=[val,val+header,val*2,val*2+header] if val is not None else []
        cands=[c for c in cands if c and header<=c<=4096 and pos+c<=len(data)]
        if not cands:
            pos+=1
            continue
        size=min(cands,key=lambda c:abs(c-96))
        out.append((pos,pos+size,size)); pos+=size
    return out
if __name__=="__main__":
    pcap=Path(sys.argv[1]) if len(sys.argv)>1 else PCAP
    packets=parse_pcapng(pcap); world=detect_world_port(packets); data=stream_bytes(packets,world,"S2C")
    frames=split(data); sizes=[f[2] for f in frames]
    med=sorted(sizes)[len(sizes)//2] if sizes else ""
    print("model_id,world_port,frames,total_bytes,median_size")
    print(f"{MODEL['combined_model_id']},{world},{len(frames)},{sum(sizes)},{med}")
