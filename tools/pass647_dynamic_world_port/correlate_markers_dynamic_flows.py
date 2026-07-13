#!/usr/bin/env python3
from __future__ import annotations

import argparse, csv, datetime as dt
from collections import Counter, defaultdict
from pathlib import Path
from pcap_dynamic import iso_time, parse_pcapng, write_csv

REPO = Path(__file__).resolve().parents[2]
DEFAULT_PCAP = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")


def parse_ts(s: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try: return dt.datetime.strptime(s.strip(), fmt).timestamp()
        except Exception: pass
    return None


def classify_channel(text: str, notes: str) -> str:
    n = notes.lower()
    if "whisper" in n: return "whisper"
    if "group" in n or text.endswith("G"): return "group"
    return "unknown"


def strong_markers(path: Path) -> list[dict]:
    rows=[]
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        for i,row in enumerate(csv.DictReader(f),1):
            text=(row.get("visible_text") or "").strip()
            direction=(row.get("direction") or "").upper()
            if direction=="S2C" and text.startswith("S2C_ORACLE_") and len(text)>=16 and ("whisper" in (row.get("notes", "").lower()) or "group" in (row.get("notes", "").lower())):
                rows.append({"marker_index":i,"marker_text":text,"channel_guess":classify_channel(text,row.get("notes", "")),"logged_time":row.get("timestamp_local", ""),"ts":parse_ts(row.get("timestamp_local", "")),"notes":row.get("notes", "")})
    return rows


def nearest(pkts, ts, max_delta):
    if ts is None: return None
    cand=[p for p in pkts if p.ts is not None and abs(p.ts-ts)<=max_delta]
    if not cand: return None
    return min(cand, key=lambda p: abs(p.ts-ts))


def nearest_any(pkts, ts):
    if not pkts: return None
    if ts is None: return pkts[0]
    cand=[p for p in pkts if p.ts is not None]
    return min(cand, key=lambda p: abs(p.ts-ts)) if cand else pkts[0]


def dms(pkt, ts):
    if pkt is None or pkt.ts is None or ts is None: return ""
    return int(round((pkt.ts-ts)*1000))


def window_label(s, c):
    vals=[]
    for p in (s,c):
        if p is None: continue
        vals.append(abs(dms(p, 0) if False else 0))
    return ""


def correlate(pcap: Path, log: Path, out_corr: Path, out_summary: Path):
    markers=strong_markers(log)
    packets=parse_pcapng(pcap)
    flow_defs=[("world_game_candidate",7780), ("chat_sidechannel_candidate",10242)]
    rows=[]
    summary=[]
    for role,port in flow_defs:
        s2c=[p for p in packets if p.server_port_guess==port and p.direction_guess=="S2C" and p.payload_len>0]
        c2s=[p for p in packets if p.server_port_guess==port and p.direction_guess=="C2S" and p.payload_len>0]
        conf_counts=Counter()
        s_lens=[]; c_lens=[]
        for m in markers:
            ts=m["ts"]
            s=c=None; conf="whole_flow_fallback"; reason="whole-flow fallback used"
            for win,label in ((3,"exact_window_3s"),(10,"window_10s"),(30,"window_30s")):
                s=nearest(s2c,ts,win); c=nearest(c2s,ts,win)
                if s or c:
                    conf=label; reason=f"nearest packets found within +/-{win} seconds"; break
            if s is None and c is None:
                s=nearest_any(s2c,ts); c=nearest_any(c2s,ts)
            if s: s_lens.append(s.payload_len)
            if c: c_lens.append(c.payload_len)
            conf_counts[conf]+=1
            rows.append({"marker_index":m["marker_index"],"marker_text":m["marker_text"],"channel_guess":m["channel_guess"],"logged_time":m["logged_time"],"flow_role":role,"server_port":port,"nearest_s2c_frame":s.frame if s else "","nearest_s2c_time":iso_time(s.ts) if s else "","delta_ms":dms(s,ts),"s2c_tcp_len":s.payload_len if s else "","nearest_c2s_frame":c.frame if c else "","nearest_c2s_time":iso_time(c.ts) if c else "","c2s_delta_ms":dms(c,ts),"c2s_tcp_len":c.payload_len if c else "","confidence":conf,"reason":reason})
        summary.append({"flow_role":role,"server_port":port,"markers_with_exact_window":conf_counts["exact_window_3s"],"markers_with_10s_window":conf_counts["window_10s"],"markers_with_30s_window":conf_counts["window_30s"],"total_markers":len(markers),"typical_s2c_lengths":";".join(f"{k}x{v}" for k,v in Counter(s_lens).most_common(6)),"typical_c2s_lengths":";".join(f"{k}x{v}" for k,v in Counter(c_lens).most_common(6)),"confidence":"high" if conf_counts["exact_window_3s"]>=5 else "medium" if conf_counts["exact_window_3s"]+conf_counts["window_10s"]>=5 else "low","reason":"marker timing evidence summarized from nearest safe packet metadata"})
    write_csv(out_corr, rows, ["marker_index","marker_text","channel_guess","logged_time","flow_role","server_port","nearest_s2c_frame","nearest_s2c_time","delta_ms","s2c_tcp_len","nearest_c2s_frame","nearest_c2s_time","c2s_delta_ms","c2s_tcp_len","confidence","reason"])
    write_csv(out_summary, summary, ["flow_role","server_port","markers_with_exact_window","markers_with_10s_window","markers_with_30s_window","total_markers","typical_s2c_lengths","typical_c2s_lengths","confidence","reason"])
    return {"markers":len(markers),"rows":len(rows)}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--pcap",type=Path,default=DEFAULT_PCAP); ap.add_argument("--log",type=Path,default=DEFAULT_LOG)
    ap.add_argument("--out-correlation",type=Path,default=REPO/"artifacts"/"pass647_marker_correlation_7780_10242.csv")
    ap.add_argument("--out-summary",type=Path,default=REPO/"artifacts"/"pass647_flow_marker_evidence_summary.csv")
    ns=ap.parse_args(); print(correlate(ns.pcap,ns.log,ns.out_correlation,ns.out_summary)); return 0
if __name__=="__main__": raise SystemExit(main())

