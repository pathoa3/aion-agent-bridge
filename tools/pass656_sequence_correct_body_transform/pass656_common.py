#!/usr/bin/env python3
from __future__ import annotations
import csv, datetime as dt, json, math, statistics, struct, sys, zlib, gzip, subprocess
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, Counter

REPO=Path(__file__).resolve().parents[2]
ART=REPO/"artifacts"
TOOL=REPO/"tools"/"pass656_sequence_correct_body_transform"
GEN=TOOL/"generated_parsers"
INBOX=REPO/"inbox"
PCAP=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOCAL_OUT=Path(r"C:\AionTools\aion_decoder_agent\outbox\pass656_sequence_correct_body_transform")
SERVER_IP="51.83.147.97"
SIDE_PORT=10242
QUEUE=ART/"pass656_work_queue.json"

@dataclass
class TcpSeg:
    frame:int; ts:float|None; src_ip:str; src_port:int; dst_ip:str; dst_port:int; seq:int; ack:int; flags:int; payload:bytes
    @property
    def payload_len(self): return len(self.payload)
    @property
    def server_port_guess(self):
        for p in (self.src_port,self.dst_port):
            if p in (2106,10242,11000) or 7770<=p<=7799: return p
        return None
    @property
    def direction_guess(self):
        port=self.server_port_guess
        if self.src_ip==SERVER_IP and self.src_port==port: return "S2C"
        if self.dst_ip==SERVER_IP and self.dst_port==port: return "C2S"
        return "unknown"

def iso(ts):
    if ts is None: return ""
    return dt.datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="milliseconds")

def parse_ts(s): return dt.datetime.strptime(s,"%Y-%m-%d %H:%M:%S").timestamp()

def oracles():
    rows=[
("whisper","Spirips","2026-07-13 21:17:21","S2C_A_0001_XXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:17:34","S2C_A_0001_XXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:18:02","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:18:20","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:19:17","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:19:30","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:20:08","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:20:18","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
("group","Spirips","2026-07-13 21:20:52","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:21:07","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:21:36","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:22:48","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:19","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:26","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:51","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:58","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),
("local","Seahlt","2026-07-13 21:24:30","S2C_ORACLE_SAY_TEST_001")]
    out=[]
    for i,(ch,sp,t,txt) in enumerate(rows,1):
        start=parse_ts(t); out.append({"oracle_id":f"o{i:03d}","channel":ch,"speaker":sp,"visible_text":txt,"text_length":len(txt),"start":start,"end":start+0.999,"mid":start+0.499})
    return out

def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader();
        for r in rows: w.writerow({k:r.get(k,"") for k in fields})

def read_csv(path):
    if not path.exists(): return []
    with path.open("r",newline="",encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def write_json(path,data): path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")

def read_options(data,endian):
    opts=defaultdict(list); off=0
    while off+4<=len(data):
        code,length=struct.unpack_from(endian+"HH",data,off); off+=4
        if code==0: break
        val=data[off:off+length]; opts[code].append(val); off+=length; off+=(-length)%4
    return opts

def ts_res(opts):
    vals=opts.get(9) or []
    if not vals: return 1e-6
    v=vals[0][0]
    return 2**-(v&0x7f) if v&0x80 else 10**-v

def parse_tcp(packet_data):
    if len(packet_data)<14: return None
    off=14; eth=struct.unpack_from("!H",packet_data,12)[0]
    while eth in (0x8100,0x88A8) and len(packet_data)>=off+4:
        eth=struct.unpack_from("!H",packet_data,off+2)[0]; off+=4
    if eth!=0x0800 or len(packet_data)<off+20: return None
    ihl=(packet_data[off]&0x0f)*4
    if ihl<20 or packet_data[off+9]!=6: return None
    total=struct.unpack_from("!H",packet_data,off+2)[0]; ip_end=min(off+total,len(packet_data))
    src=".".join(str(x) for x in packet_data[off+12:off+16]); dst=".".join(str(x) for x in packet_data[off+16:off+20])
    toff=off+ihl
    if len(packet_data)<toff+20: return None
    sp,dp=struct.unpack_from("!HH",packet_data,toff); seq,ack=struct.unpack_from("!II",packet_data,toff+4)
    data_off=((packet_data[toff+12]>>4)&0x0f)*4; flags=packet_data[toff+13]
    poff=toff+data_off; payload=b"" if poff>ip_end else packet_data[poff:ip_end]
    return src,sp,dst,dp,seq,ack,flags,payload

def parse_pcapng_seq(path=PCAP):
    data=path.read_bytes(); endian="<"; ifaces={}; off=0; frame=0; segs=[]
    while off+12<=len(data):
        block=struct.unpack_from(endian+"I",data,off)[0]; blen=struct.unpack_from(endian+"I",data,off+4)[0]
        if block==0x0A0D0D0A:
            le=struct.unpack_from("<I",data,off+4)[0]; be=struct.unpack_from(">I",data,off+4)[0]; blen=le if 12<=le<=len(data)-off else be
            magic=data[off+8:off+12]; endian="<" if magic==b"\x4d\x3c\x2b\x1a" else ">" if magic==b"\x1a\x2b\x3c\x4d" else endian; ifaces={}
        if blen<12 or off+blen>len(data): break
        body=data[off+8:off+blen-4]
        if block==1 and len(body)>=8:
            link=struct.unpack_from(endian+"H",body,0)[0]; opts=read_options(body[8:],endian); ifaces[len(ifaces)]=(link,ts_res(opts))
        elif block==6 and len(body)>=20:
            frame+=1; iface,hi,lo,cap,_orig=struct.unpack_from(endian+"IIIII",body,0); link,res=ifaces.get(iface,(1,1e-6)); pkt=body[20:20+cap]
            if link==1:
                parsed=parse_tcp(pkt)
                if parsed:
                    src,sp,dst,dp,seq,ack,flags,payload=parsed; ts=((hi<<32)|lo)*res; segs.append(TcpSeg(frame,ts,src,sp,dst,dp,seq,ack,flags,payload))
        off+=blen
    return segs

def detect_world(segs):
    stats=defaultdict(lambda:{"bytes":0,"packets":0,"first":None,"last":None})
    for s in segs:
        p=s.server_port_guess
        if p and 7770<=p<=7799 and s.payload_len:
            d=stats[p]; d["bytes"]+=s.payload_len; d["packets"]+=1; d["first"]=s.ts if d["first"] is None else min(d["first"],s.ts); d["last"]=s.ts if d["last"] is None else max(d["last"],s.ts)
    return max(stats,key=lambda p:(stats[p]["bytes"],stats[p]["packets"],(stats[p]["last"] or 0)-(stats[p]["first"] or 0))) if stats else None

def flow(segs,port,direction=None):
    xs=[s for s in segs if s.server_port_guess==port and s.payload_len]
    if direction: xs=[s for s in xs if s.direction_guess==direction]
    return sorted(xs,key=lambda s:(s.ts,s.frame))

def reassemble_by_seq(segs):
    if not segs: return b"", [], {"segments":0,"duplicates":0,"overlaps":0,"gaps":0,"out_of_order":0,"bytes":0}
    ordered=sorted(segs,key=lambda s:(s.seq,s.frame)); base=min(s.seq for s in ordered); pieces=[]; pos=base; dups=overlaps=gaps=ooo=0; ranges=[]; data=bytearray()
    seen=set(); last_capture_seq=None
    for s in sorted(segs,key=lambda s:(s.ts,s.frame)):
        if last_capture_seq is not None and s.seq<last_capture_seq: ooo+=1
        last_capture_seq=s.seq
    for s in ordered:
        key=(s.seq,s.payload_len,s.payload[:8])
        if key in seen: dups+=1; continue
        seen.add(key)
        if s.seq<pos:
            overlap=pos-s.seq; overlaps+=1
            payload=s.payload[overlap:] if overlap<len(s.payload) else b""
            start=pos
        elif s.seq>pos:
            gaps+=1; data.extend(b"\x00"*(s.seq-pos)); start=s.seq; pos=s.seq; payload=s.payload
        else:
            start=s.seq; payload=s.payload
        off=len(data); data.extend(payload); endoff=len(data); pos=start+len(payload); ranges.append({"frame":s.frame,"seq_start":s.seq,"seq_end":s.seq+s.payload_len,"stream_offset_start":off,"stream_offset_end":endoff,"time":iso(s.ts),"tcp_len":s.payload_len})
    return bytes(data), ranges, {"segments":len(segs),"duplicates":dups,"overlaps":overlaps,"gaps":gaps,"out_of_order":ooo,"bytes":len(data)}

def capture_order_bytes(segs): return b"".join(s.payload for s in sorted(segs,key=lambda s:(s.ts,s.frame)))

def nearest(xs,ts): return min(xs,key=lambda s:abs((s.ts or 0)-ts)) if xs else None

def win(xs,start,end): return [s for s in xs if s.ts is not None and start<=s.ts<=end]

def reps(text,speaker="",channel=""):
    out=[]
    def add(n,b):
        if b: out.append((n,b))
    add("ascii",text.encode("ascii",errors="ignore")); add("utf16le",text.encode("utf-16le")); add("utf16be",text.encode("utf-16be")); add("nul_ascii",b"\x00".join(bytes([x]) for x in text.encode("ascii",errors="ignore")))
    add("no_underscore",text.replace("_","").encode("ascii",errors="ignore")); parts=text.split("_")
    if len(parts)>=3: add("numeric",parts[2].encode("ascii",errors="ignore"))
    xr="X"*text.count("X")
    if xr: add("x_run",xr.encode("ascii"))
    for token,label in [(speaker,"sender"),(channel,"channel"),(speaker+" "+text,"sender_marker"),(channel+" "+speaker+" "+text,"channel_sender_marker")]:
        if token.strip(): add(label+"_ascii",token.encode("ascii",errors="ignore")); add(label+"_utf16le",token.encode("utf-16le"))
    seen=set(); res=[]
    for n,b in out:
        if (n,b) not in seen: seen.add((n,b)); res.append((n,b))
    return res

def split_frames(data, model):
    h=int(model.get("header_size",model.get("header",4))); off=int(model.get("length_field_offset",0)); w=int(model.get("length_width",2)); endian=model.get("endianness","little")
    frames=[]; pos=0; invalid=0; resync=0
    while pos+h<=len(data) and len(frames)<10000:
        val=int.from_bytes(data[pos+off:pos+off+w], endian) if pos+off+w<=len(data) else 0
        cands=[]
        for size in (val, val+h, val*2, val*2+h, val-h if val>h else 0):
            if h<=size<=4096 and pos+size<=len(data): cands.append(size)
        if not cands:
            invalid+=1; pos+=1; resync+=1; continue
        size=cands[0]
        frames.append((pos,pos+size,h,size)); pos+=size
    return frames,{"frames":len(frames),"coverage":round((frames[-1][1] if frames else 0)/max(1,len(data)),4),"invalid":invalid,"resync":resync}

def entropy(b):
    if not b: return 0
    c=Counter(b); n=len(b); return round(-sum((v/n)*math.log2(v/n) for v in c.values()),3)

def transform_variants(body, train_text=None):
    vars=[("identity",body),("bit_not",bytes((~x)&255 for x in body)),("nibble_swap",bytes(((x&15)<<4)|((x>>4)&15) for x in body)),("rot1",bytes(((x<<1)&255)|(x>>7) for x in body)),("swap16",b"".join(body[i:i+2][::-1] for i in range(0,len(body),2))),("swap32",b"".join(body[i:i+4][::-1] for i in range(0,len(body),4)))]
    if train_text:
        plain=train_text.encode("ascii",errors="ignore")
        for klen in (1,2,4,8,16,32,64):
            if len(body)>=klen and plain:
                key=bytes(body[i]^plain[i%len(plain)] for i in range(klen))
                vars.append((f"xor_derived_k{klen}", bytes(b^key[i%klen] for i,b in enumerate(body))))
    return vars

def contains_known(data,o):
    hit=[]
    for name,needle in reps(o["visible_text"],o["speaker"],o["channel"]):
        if needle and data.find(needle)>=0: hit.append(name)
    return hit

def contains_exact_message(data,o):
    text=o["visible_text"]
    needles=[text.encode("ascii",errors="ignore"), text.encode("utf-16le"), text.encode("utf-16be"), b"\x00".join(bytes([x]) for x in text.encode("ascii",errors="ignore"))]
    return any(n and data.find(n)>=0 for n in needles)
