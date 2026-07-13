#!/usr/bin/env python3
from pass655_common import *
PARSER_TEMPLATE = r'''#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/"tools"/"pass655_world_framing_marathon"))
from pass655_common import parse_pcapng, detect_world_port, stream_bytes, len_read, PCAP
MODEL=__MODEL__
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
'''
def main():
    GEN.mkdir(parents=True, exist_ok=True)
    models=read_csv(ART/"pass655_wire_parser_models.csv"); rows=[]
    for m in models:
        path=GEN/f"parser_{m['combined_model_id']}.py"
        text=PARSER_TEMPLATE.replace("__MODEL__", repr(dict(m)))
        path.write_text(text, encoding="ascii")
        rows.append({"parser_id":m["combined_model_id"],"parser_path":str(path),"frame_model_id":m["frame_model_id"],"header_size":m["header_size"],"length_rule":m["length_rule"],"generated":"true","confidence":m["confidence"],"reason":"complete runnable offline parser candidate; emits numeric metadata only"})
    safe_write_csv(ART/"pass655_generated_parser_inventory.csv", rows, ["parser_id","parser_path","frame_model_id","header_size","length_rule","generated","confidence","reason"])
    print({"stage":"10","parsers":len(rows)})
if __name__=="__main__": main()
