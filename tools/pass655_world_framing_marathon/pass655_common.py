#!/usr/bin/env python3
from __future__ import annotations
import csv, datetime as dt, json, math, statistics, sys, os
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
INBOX = REPO / "inbox"
TOOL = REPO / "tools" / "pass655_world_framing_marathon"
GEN = TOOL / "generated_parsers"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
LOCAL_OUT = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass655_world_framing_marathon")
EUROAION_SERVER_IP="51.83.147.97"
SIDE_PORT=10242; LOGIN_PORT=2106; AUX_PORT=11000
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore

def read_csv(path: Path):
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")

def parse_ts(s: str):
    s=(s or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S"):
        try: return dt.datetime.strptime(s,fmt).timestamp()
        except Exception: pass
    return None

def authoritative_oracles():
    data=[
("whisper","Spirips","2026-07-13 21:17:21","S2C_A_0001_XXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:17:34","S2C_A_0001_XXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:18:02","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:18:20","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:19:17","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:19:30","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:20:08","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("whisper","Spirips","2026-07-13 21:20:18","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
("group","Spirips","2026-07-13 21:20:52","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:21:07","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:21:36","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:22:48","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:19","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:26","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:51","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("group","Spirips","2026-07-13 21:23:58","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),
("local","Seahlt","2026-07-13 21:24:30","S2C_ORACLE_SAY_TEST_001")]
    rows=[]
    for i,(chan,speaker,ts_s,text) in enumerate(data,1):
        start=parse_ts(ts_s); end=start+0.999 if start is not None else None
        rows.append({"oracle_id":f"o{i:03d}","channel":chan,"speaker":speaker,"visible_text":text,"text_length":len(text.encode("ascii",errors="ignore")),"chatlog_second_start":iso_time(start),"chatlog_second_end":iso_time(end),"ts_start":start,"ts_end":end,"ts_mid":start+0.499 if start is not None else None,"primary_source":"authoritative_chat_log","manual_note_present":False,"manual_note_used_for_scoring":False,"strong_reference":True,"reason":"hardcoded from Pass655 authoritative chat.log rows; manual note timestamps ignored"})
    return rows

def flow_key(p):
    port=p.server_port_guess
    if p.src_ip==EUROAION_SERVER_IP and p.src_port==port: return (p.src_ip,p.src_port,p.dst_ip,p.dst_port)
    if p.dst_ip==EUROAION_SERVER_IP and p.dst_port==port: return (p.dst_ip,p.dst_port,p.src_ip,p.src_port)
    return (p.src_ip,p.src_port,p.dst_ip,p.dst_port)

def pkts(packets, port=None, direction=None, payload=True):
    rows=[p for p in packets if p.ts is not None and (port is None or p.server_port_guess==port)]
    if direction: rows=[p for p in rows if p.direction_guess==direction]
    if payload: rows=[p for p in rows if p.payload_len>0]
    return sorted(rows, key=lambda p:(p.ts,p.frame))

def detect_world_port(packets):
    stats=defaultdict(lambda:{"packets":0,"bytes":0,"first":None,"last":None})
    for p in packets:
        port=p.server_port_guess
        if port and 7770<=port<=7799 and p.payload_len>0:
            d=stats[port]; d["packets"]+=1; d["bytes"]+=p.payload_len; d["first"]=p.ts if d["first"] is None else min(d["first"],p.ts); d["last"]=p.ts if d["last"] is None else max(d["last"],p.ts)
    if not stats: return None
    return max(stats, key=lambda k:(stats[k]["bytes"],stats[k]["packets"],(stats[k]["last"] or 0)-(stats[k]["first"] or 0)))

def nearest(rows, ts):
    if ts is None or not rows: return None
    return min(rows, key=lambda p:abs(p.ts-ts))

def delta_ms(p, ts):
    if not p or ts is None: return ""
    return int(round((p.ts-ts)*1000))

def in_interval(p, o):
    return o["ts_start"] <= p.ts <= o["ts_end"]

def window_pkts(packets, port, direction, center, sec):
    return [p for p in pkts(packets,port,direction) if center is not None and abs(p.ts-center)<=sec]

def oracle_window_pkts(packets, port, direction, o, model):
    if model=="exact_second": return [p for p in pkts(packets,port,direction) if in_interval(p,o)]
    if model.startswith("pm"):
        sec=float(model[2:].replace("_",".")); return window_pkts(packets,port,direction,o["ts_mid"],sec)
    return []

def stream_index(packets, port, direction):
    off=0; rows=[]
    for p in pkts(packets,port,direction):
        rows.append((p,off,off+p.payload_len)); off+=p.payload_len
    return rows

def stream_bytes(packets, port, direction):
    return b"".join(p.payload for p in pkts(packets,port,direction))

def len_read(data, off, width, endian):
    if off+width>len(data): return None
    return int.from_bytes(data[off:off+width], "little" if endian=="little" else "big")

def message_reps(text, speaker="", channel=""):
    vals=[]
    def add(n,b):
        if b: vals.append((n,b))
    add("ascii", text.encode("ascii",errors="ignore")); add("utf16le", text.encode("utf-16le")); add("utf16be", text.encode("utf-16be")); add("nul_ascii", b"\x00".join(bytes([x]) for x in text.encode("ascii",errors="ignore")))
    add("no_underscore", text.replace("_","").encode("ascii",errors="ignore"))
    parts=text.split("_")
    if len(parts)>=3: add("numeric_marker", parts[2].encode("ascii",errors="ignore"))
    xr="X"*text.count("X")
    if xr: add("x_run", xr.encode("ascii"))
    for token,label in [(speaker,"sender"),(channel,"channel"),(speaker+" "+text,"sender_marker"),(channel+" "+speaker+" "+text,"channel_sender_marker")]:
        if token.strip():
            add(label+"_ascii", token.encode("ascii",errors="ignore")); add(label+"_utf16le", token.encode("utf-16le")); add(label+"_utf16be", token.encode("utf-16be"))
    seen=set(); out=[]
    for n,b in vals:
        k=(n,b)
        if k not in seen: seen.add(k); out.append((n,b))
    return out

def base_marker(text):
    t=text[:-1] if text.endswith("G") else text
    parts=t.split("_")
    return parts[2] if len(parts)>2 else t

def median(vals):
    vals=[float(v) for v in vals if v not in (None,"")]
    return int(round(statistics.median(vals))) if vals else ""

def bools(x): return str(bool(x)).lower()

def row_count(path):
    return len(read_csv(path))

def safe_write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True); return write_csv(path, rows, fields)
