#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv
from pathlib import Path
from pcap_dynamic import iso_time, parse_pcapng, write_csv
from correlate_markers_dynamic_flows import strong_markers
REPO=Path(__file__).resolve().parents[2]
DEFAULT_PCAP=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
DEFAULT_LOG=Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")

def variants(text):
    forms=[("marker_exact",text),("whisper_visible_form","::Spirips Whispers: "+text),("group_visible_form","Spirips: "+text)]
    for scope,value in forms:
        yield scope,"ascii",value.encode("ascii",errors="ignore")
        yield scope,"utf-16le",value.encode("utf-16le",errors="ignore")

def scan(pcap,log,out):
    markers=strong_markers(log); packets=parse_pcapng(pcap); rows=[]
    roles={7780:"world_game_candidate",10242:"chat_sidechannel_candidate"}
    for pkt in packets:
        port=pkt.server_port_guess
        if port not in roles or pkt.payload_len<=0: continue
        for m in markers:
            for scope,enc,needle in variants(m["marker_text"]):
                if needle and pkt.payload.find(needle)>=0:
                    rows.append({"flow_role":roles[port],"server_port":port,"frame":pkt.frame,"time_local":iso_time(pkt.ts),"direction":pkt.direction_guess,"tcp_len":pkt.payload_len,"text_label":m["marker_text"],"encoding":enc,"match_scope":scope,"confidence":"high_literal_match","notes":"literal text found during local-only payload scan; payload not written"})
    write_csv(out,rows,["flow_role","server_port","frame","time_local","direction","tcp_len","text_label","encoding","match_scope","confidence","notes"])
    return {"hits":len(rows)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--pcap",type=Path,default=DEFAULT_PCAP); ap.add_argument("--log",type=Path,default=DEFAULT_LOG); ap.add_argument("--out",type=Path,default=REPO/"artifacts"/"pass647_literal_text_hits_7780_10242.csv")
    ns=ap.parse_args(); print(scan(ns.pcap,ns.log,ns.out)); return 0
if __name__=="__main__": raise SystemExit(main())
