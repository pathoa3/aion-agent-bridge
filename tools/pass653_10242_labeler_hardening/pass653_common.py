#!/usr/bin/env python3
from __future__ import annotations
import csv, datetime as dt, json, math, statistics, sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
INBOX = REPO / "inbox"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
LOCAL_OUT = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass653_10242_labeler_hardening")
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore

CHAT_PORT=10242
WORLD_PORT=7780

def read_csv(path: Path) -> list[dict[str,str]]:
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")

def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S"):
        try: return dt.datetime.strptime((s or "").strip(), fmt).timestamp()
        except Exception: pass
    return None

def all_log_rows():
    if not LOG.exists(): return []
    with LOG.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def load_markers() -> list[dict]:
    rows=[]
    for r in all_log_rows():
        text=(r.get("visible_text") or "").strip(); notes=(r.get("notes") or "").lower(); direction=(r.get("direction") or "").upper()
        if direction=="S2C" and text.startswith("S2C_A_") and "whisper" in notes and not text.endswith("G"):
            rows.append({"marker_index":len(rows)+1,"marker_text":text,"marker_len_ascii":len(text.encode("ascii",errors="ignore")),"logged_time":r.get("timestamp_local",""),"ts":parse_ts(r.get("timestamp_local","")),"occurrence_index":0})
    counts=defaultdict(int)
    for r in rows:
        counts[r["marker_text"]]+=1; r["occurrence_index"]=counts[r["marker_text"]]
    return rows

def old_oracle_count():
    return sum(1 for r in all_log_rows() if (r.get("visible_text") or "").startswith("S2C_ORACLE_"))

def pkts(packets, port=None, direction=None, payload=True):
    rows=[p for p in packets if p.ts is not None and (port is None or p.server_port_guess==port)]
    if direction: rows=[p for p in rows if p.direction_guess==direction]
    if payload: rows=[p for p in rows if p.payload_len>0]
    return rows

def c2s22(packets): return [p for p in pkts(packets, CHAT_PORT, "C2S") if p.payload_len==22]
def s2c_chat(packets): return pkts(packets, CHAT_PORT, "S2C")
def world_s2c(packets): return pkts(packets, WORLD_PORT, "S2C")
def world_c2s(packets): return pkts(packets, WORLD_PORT, "C2S")

def nearest(rows, ts):
    if ts is None or not rows: return None
    return min(rows, key=lambda p: abs(p.ts-ts))

def delta_ms(pkt, ts):
    if not pkt or ts is None: return ""
    return int(round((pkt.ts-ts)*1000))

def abs_delta(pkt, ts):
    d=delta_ms(pkt, ts)
    return None if d=="" else abs(int(d))

def median(vals):
    vals=[float(v) for v in vals if v!="" and v is not None]
    return int(round(statistics.median(vals))) if vals else ""

def mean(vals):
    vals=[float(v) for v in vals if v!="" and v is not None]
    return round(sum(vals)/len(vals),3) if vals else ""

def quant_score(ms):
    if ms is None: return 0.0
    if ms<=1000: return 1.0
    if ms<=2000: return 0.75
    if ms<=4000: return 0.45
    if ms<=7000: return 0.2
    return 0.0

def window(packets, port, ts, sec, direction=None):
    return [p for p in pkts(packets, port, direction) if ts is not None and abs(p.ts-ts)<=sec]

def seq_sig(rows, ts, sec=3, limit=8):
    selected=sorted([p for p in rows if ts is not None and abs(p.ts-ts)<=sec], key=lambda p:p.ts)[:limit]
    lens="-".join(("C" if p.direction_guess=="C2S" else "S")+str(p.payload_len) for p in selected)
    dirs="".join("C" if p.direction_guess=="C2S" else "S" for p in selected)
    total=sum(p.payload_len for p in selected)
    return lens, dirs, total, len(selected)

def byte_class_name(data: bytes):
    if not data: return "empty"
    zero=data.count(0); printable=sum(1 for b in data if 32<=b<=126); high=sum(1 for b in data if b>=128)
    return f"z{zero}_p{printable}_h{high}_l{len(data)}"

def intervals_for(packet, ordered):
    try: i=ordered.index(packet)
    except ValueError: return "", ""
    prev=int(round((packet.ts-ordered[i-1].ts)*1000)) if i>0 else ""
    nxt=int(round((ordered[i+1].ts-packet.ts)*1000)) if i+1<len(ordered) else ""
    return prev,nxt

def score_event_at(packets, ts, baseline_penalty=0.0):
    c22=c2s22(packets); s2c=s2c_chat(packets); all10242=pkts(packets, CHAT_PORT)
    n22=nearest(c22, ts); d22=abs_delta(n22, ts)
    ns2c=nearest(s2c, ts); ds2c=abs_delta(ns2c, ts)
    s2c1=sum(p.payload_len for p in window(packets, CHAT_PORT, ts, 1, "S2C"))
    s2c3=sum(p.payload_len for p in window(packets, CHAT_PORT, ts, 3, "S2C"))
    s2c5=sum(p.payload_len for p in window(packets, CHAT_PORT, ts, 5, "S2C"))
    lens,dirs,total,count=seq_sig(all10242, ts, 3)
    prev_i,next_i=intervals_for(n22,c22) if n22 else ("","")
    cadence_break=False
    if prev_i!="" and next_i!="": cadence_break=abs(int(prev_i)-int(next_i))>=2500
    score=0.55*quant_score(d22)+0.2*quant_score(ds2c)+min(0.15,s2c3/1000.0)+ (0.1 if cadence_break else 0.0) - baseline_penalty
    score=max(0.0,min(1.0,score))
    conf="high" if score>=0.75 else "medium" if score>=0.45 else "low"
    return {"n22":n22,"d22":d22,"ns2c":ns2c,"ds2c":ds2c,"s2c1":s2c1,"s2c3":s2c3,"s2c5":s2c5,"lens":lens,"dirs":dirs,"total":total,"count":count,"prev_i":prev_i,"next_i":next_i,"cadence_break":cadence_break,"score":round(score,3),"confidence":conf}

def marker_windows(markers, sec):
    return [(m["ts"]-sec, m["ts"]+sec) for m in markers if m.get("ts") is not None]

def in_any(ts, ranges): return any(a<=ts<=b for a,b in ranges)

def confidence_from_count(n): return "high" if n>=8 else "medium" if n>=4 else "low"
