#!/usr/bin/env python3
from __future__ import annotations
import csv, datetime as dt, json, math, statistics, sys, zlib, gzip
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ART = REPO / "artifacts"
INBOX = REPO / "inbox"
PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
LOCAL_OUT = Path(r"C:\AionTools\aion_decoder_agent\outbox\pass654b_offline_capture_validation")
EUROAION_SERVER_IP = "51.83.147.97"
LOGIN_PORT=2106; AUX_PORT=11000; SIDE_PORT=10242
sys.path.insert(0, str(REPO / "tools" / "pass647_dynamic_world_port"))
from pcap_dynamic import parse_pcapng, iso_time, write_csv  # type: ignore

def read_csv(path: Path) -> list[dict[str,str]]:
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")

def parse_ts(s: str):
    s=(s or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S","%H:%M:%S","%H:%M"):
        try:
            d=dt.datetime.strptime(s,fmt)
            if fmt.startswith("%H"):
                d=dt.datetime(2026,7,13,d.hour,d.minute,d.second)
            return d.timestamp()
        except Exception: pass
    return None

def all_log_rows():
    if not LOG.exists(): return []
    with LOG.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))

def app_rows():
    whisper=[("21:17:21","Spirips","S2C_A_0001_XXXXXXXXXXXXXXXX"),("21:17:34","Spirips","S2C_A_0001_XXXXXXXXXXXXXXXX"),("21:18:02","Spirips","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("21:18:20","Spirips","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXX"),("21:19:17","Spirips","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("21:19:30","Spirips","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("21:20:08","Spirips","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),("21:20:18","Spirips","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")]
    group=[("21:20:52","Spirips","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("21:21:07","Spirips","S2C_A_0001_XXXXXXXXXXXXXXXXG"),("21:21:36","Spirips","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("21:22:48","Spirips","S2C_A_0002_XXXXXXXXXXXXXXXXXXXXXXXXG"),("21:23:19","Spirips","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("21:23:26","Spirips","S2C_A_0003_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("21:23:51","Spirips","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG"),("21:23:58","Spirips","S2C_A_0004_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXG")]
    rows=[]
    for t,s,msg in whisper: rows.append({"source":"prompt_app_rows","channel":"whisper","speaker":s,"visible_text":msg,"app_time":"2026-07-13 "+t})
    for t,s,msg in group: rows.append({"source":"prompt_app_rows","channel":"group","speaker":s,"visible_text":msg,"app_time":"2026-07-13 "+t})
    rows.append({"source":"prompt_app_rows","channel":"local","speaker":"Seahlt","visible_text":"S2C_ORACLE_SAY_TEST_001","app_time":"2026-07-13 21:24:30"})
    return rows

def merged_oracles():
    log_by_text=defaultdict(list)
    stale=[]
    for r in all_log_rows():
        txt=(r.get("visible_text") or "").strip(); ts=(r.get("timestamp_local") or "").strip()
        if txt.startswith("S2C_A_"): log_by_text[txt].append(ts)
        elif txt.startswith("S2C_ORACLE_SAY_TEST_001"): log_by_text[txt].append(ts)
        elif txt.startswith("S2C_ORACLE_"): stale.append((txt,ts))
    rows=[]; idx=1; text_seen=defaultdict(int)
    for r in app_rows():
        txt=r["visible_text"]; text_seen[txt]+=1
        logs=log_by_text.get(txt,[]); logged=logs[text_seen[txt]-1] if text_seen[txt]-1 < len(logs) else ""
        app_ts=parse_ts(r["app_time"]); log_ts=parse_ts(logged)
        chosen=log_ts if log_ts is not None else app_ts
        tol=1000 if log_ts is not None else 5000
        rows.append({"oracle_id":f"o{idx:03d}","source":r["source"]+("+known_log" if logged else ""),"channel":r["channel"],"speaker":r["speaker"],"visible_text":txt,"text_length":len(txt.encode("ascii",errors="ignore")),"app_time":r["app_time"],"logged_time":logged,"chosen_time":iso_time(chosen),"ts":chosen,"time_tolerance_ms":tol,"current_capture":True,"strong_reference":r["channel"] in ("whisper","group","local"),"reason":"current prompt oracle row; known log time preferred when available"}); idx+=1
    for txt,logged in stale:
        rows.append({"oracle_id":f"o{idx:03d}","source":"known_log_stale","channel":"stale","speaker":"","visible_text":txt,"text_length":len(txt),"app_time":"","logged_time":logged,"chosen_time":logged,"ts":parse_ts(logged),"time_tolerance_ms":0,"current_capture":False,"strong_reference":False,"reason":"stale S2C_ORACLE row retained only for accounting"}); idx+=1
    return rows

def pkts(packets, port=None, direction=None, payload=True):
    rows=[p for p in packets if p.ts is not None and (port is None or p.server_port_guess==port)]
    if direction: rows=[p for p in rows if p.direction_guess==direction]
    if payload: rows=[p for p in rows if p.payload_len>0]
    return rows

def flow_key(p):
    port=p.server_port_guess
    if p.src_ip==EUROAION_SERVER_IP and p.src_port==port: return (p.src_ip,p.src_port,p.dst_ip,p.dst_port)
    if p.dst_ip==EUROAION_SERVER_IP and p.dst_port==port: return (p.dst_ip,p.dst_port,p.src_ip,p.src_port)
    return (p.src_ip,p.src_port,p.dst_ip,p.dst_port)

def detect_world_port(packets):
    c=defaultdict(lambda:{"packets":0,"bytes":0,"first":None,"last":None})
    for p in packets:
        port=p.server_port_guess
        if port is not None and 7770<=port<=7799 and p.payload_len>0:
            d=c[port]; d["packets"]+=1; d["bytes"]+=p.payload_len; d["first"]=p.ts if d["first"] is None else min(d["first"],p.ts); d["last"]=p.ts if d["last"] is None else max(d["last"],p.ts)
    if not c: return None
    return max(c, key=lambda port:(c[port]["bytes"],c[port]["packets"],(c[port]["last"] or 0)-(c[port]["first"] or 0)))

def nearest(rows, ts):
    if ts is None or not rows: return None
    return min(rows, key=lambda p: abs(p.ts-ts))

def delta_ms(p, ts):
    if p is None or ts is None: return ""
    return int(round((p.ts-ts)*1000))

def window_pkts(packets, port, ts, sec, direction=None):
    return [p for p in pkts(packets,port,direction) if ts is not None and abs(p.ts-ts)<=sec]

def stream_indices(packets, port, direction):
    off=0; out=[]
    for p in sorted(pkts(packets,port,direction), key=lambda x:(x.ts,x.frame)):
        out.append((p,off,off+p.payload_len)); off+=p.payload_len
    return out

def bytes_for_window(packets, port, direction, ts, sec):
    return b"".join(p.payload for p in sorted(window_pkts(packets,port,ts,sec,direction), key=lambda x:(x.ts,x.frame)))

def reps(text, speaker="", channel=""):
    vals=[]
    core=[("ascii", text.encode("ascii",errors="ignore")),("utf16le", text.encode("utf-16le")),("utf16be", text.encode("utf-16be")),("nul_ascii", b"\x00".join(bytes([b]) for b in text.encode("ascii",errors="ignore"))),("no_underscore", text.replace("_","").encode("ascii",errors="ignore"))]
    parts=text.split("_")
    if len(parts)>=3: core.append(("numeric_marker", parts[2].encode("ascii",errors="ignore")))
    xr="X"*text.count("X")
    if xr: core.append(("x_run", xr.encode("ascii")))
    for name in [speaker, "Spirips", "Seahlt", "Whisper", "Group", "Spirips:", "::Spirips Whispers:", "Spirips Whispers:"]:
        if name: core += [("token_ascii_"+name[:8], name.encode("ascii",errors="ignore")),("token_utf16le_"+name[:8], name.encode("utf-16le")),("token_utf16be_"+name[:8], name.encode("utf-16be"))]
    seen=set()
    for k,v in core:
        if v and (k,v) not in seen:
            seen.add((k,v)); vals.append((k,v))
    return vals

def find_rep(data, needle, offsets=range(0,33)):
    if not needle: return False
    if data.find(needle)>=0: return True
    for o in offsets:
        if len(data)>o and data[o:].find(needle)>=0: return True
    return False

def length_seq(rows, ts, sec=3, limit=10):
    xs=sorted([p for p in rows if ts is not None and abs(p.ts-ts)<=sec], key=lambda p:(p.ts,p.frame))[:limit]
    return "-".join(("C" if p.direction_guess=="C2S" else "S")+str(p.payload_len) for p in xs), "".join("C" if p.direction_guess=="C2S" else "S" for p in xs), sum(p.payload_len for p in xs)

def median(vals):
    vals=[float(v) for v in vals if v not in (None,"")]
    return int(round(statistics.median(vals))) if vals else ""

def bools(x): return str(bool(x)).lower()
