#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from pcap_dynamic import parse_pcapng, write_csv
from correlate_markers_dynamic_flows import strong_markers
REPO=Path(__file__).resolve().parents[2]
DEFAULT_PCAP=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")

def readiness(pcap,log,out):
    packets=parse_pcapng(pcap); markers=strong_markers(log); first_marker=min((m["ts"] for m in markers if m["ts"] is not None), default=None)
    world=[p for p in packets if p.server_port_guess==7780]
    before=[p for p in world if first_marker is not None and p.ts is not None and p.ts < first_marker]
    s2c=[p for p in before if p.direction_guess=="S2C"]; c2s=[p for p in before if p.direction_guess=="C2S"]
    ready=bool(world and len(before)>=50 and len(s2c)>=10 and len(c2s)>=10)
    capture_started=bool(world and first_marker is not None and min(p.ts for p in world if p.ts is not None) < first_marker)
    row={"actual_world_port":7780,"world_flow_found":str(bool(world)).lower(),"packets_before_first_marker":len(before),"s2c_packets_before_first_marker":len(s2c),"c2s_packets_before_first_marker":len(c2s),"capture_started_before_world_flow":str(capture_started).lower(),"ready_for_s2c_oracle_attempt":str(ready).lower(),"reason":"enough 7780 packets exist before first marker for rolling-state S2C analysis" if ready else "insufficient pre-marker 7780 packet context"}
    write_csv(out,[row],["actual_world_port","world_flow_found","packets_before_first_marker","s2c_packets_before_first_marker","c2s_packets_before_first_marker","capture_started_before_world_flow","ready_for_s2c_oracle_attempt","reason"])
    local=Path(r"C:\AionTools\aion_decoder_agent\outbox\pass647_dynamic_world_7780")
    local.mkdir(parents=True, exist_ok=True)
    (local/"README_SAFE_METADATA_ONLY.txt").write_text("Local-only Pass647 7780 oracle workspace. No raw packet data written by bridge script.\n", encoding="utf-8")
    return row

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--pcap",type=Path,default=DEFAULT_PCAP); ap.add_argument("--log",type=Path,default=DEFAULT_LOG); ap.add_argument("--out",type=Path,default=REPO/"artifacts"/"pass647_7780_s2c_oracle_readiness.csv")
    ns=ap.parse_args(); print(json.dumps(readiness(ns.pcap,ns.log,ns.out),indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
