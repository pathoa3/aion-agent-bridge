#!/usr/bin/env python3
from __future__ import annotations

import csv, datetime as dt, json, math, sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
LOCAL_OUT = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass652_10242_event_model")
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")

def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try: return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except Exception: pass
    return None

def load_markers() -> list[dict]:
    rows=[]
    with LOG.open("r", newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            text=(r.get("visible_text") or "").strip(); notes=(r.get("notes") or "").lower(); direction=(r.get("direction") or "").upper()
            if direction=="S2C" and text.startswith("S2C_A_") and "whisper" in notes and not text.endswith("G"):
                rows.append({"marker_index":len(rows)+1,"marker_text":text,"marker_len_ascii":len(text.encode("ascii",errors="ignore")),"logged_time":r.get("timestamp_local",""),"ts":parse_ts(r.get("timestamp_local","")),"occurrence_index":0})
    counts=defaultdict(int)
    for r in rows:
        counts[r["marker_text"]]+=1; r["occurrence_index"]=counts[r["marker_text"]]
    return rows

def packets_10242(packets, direction=None):
    rows=[p for p in packets if p.server_port_guess==10242 and p.payload_len>0 and p.ts is not None]
    if direction: rows=[p for p in rows if p.direction_guess==direction]
    return rows

def entropy(data: bytes) -> float:
    if not data: return 0.0
    c=Counter(data); n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def byte_class(data: bytes) -> dict[str,float]:
    if not data: return {"zero":0,"printable":0,"utf16":0,"entropy":0,"var_positions":0}
    zero=data.count(0)/len(data); printable=sum(1 for b in data if 32<=b<=126)/len(data)
    odd_count=max(1,len(range(1,len(data),2))); utf=sum(1 for i in range(1,len(data),2) if data[i]==0)/odd_count
    return {"zero":zero,"printable":printable,"utf16":utf,"entropy":entropy(data),"var_positions":0}

def nearest(pkts, ts):
    if ts is None or not pkts: return None
    return min(pkts, key=lambda p: abs(p.ts-ts))

def next_s2c_after(s2c, ts):
    cand=[p for p in s2c if ts is not None and p.ts>=ts]
    return cand[0] if cand else None

def delta_ms(pkt, ts):
    if not pkt or ts is None: return ""
    return int(round((pkt.ts-ts)*1000))

def win_packets(packets, marker, sec):
    ts=marker["ts"]
    return [p for p in packets_10242(packets) if ts is not None and abs(p.ts-ts)<=sec]

def repeat_consistency_by_text(rows, value_key):
    vals=defaultdict(list)
    for r in rows:
        v=r.get(value_key,"")
        if v!="": vals[r["marker_text"]].append(str(v))
    comparable=[len(set(v))==1 for v in vals.values() if len(v)>=2]
    return bool(comparable) and all(comparable)

def signature_bucket_delta(ms):
    if ms=="": return "none"
    ms=int(ms); a=abs(ms)
    if a<=500: b="sub500"
    elif a<=1500: b="sub1500"
    elif a<=3000: b="sub3000"
    else: b="late"
    return ("pre_" if ms<0 else "post_")+b
