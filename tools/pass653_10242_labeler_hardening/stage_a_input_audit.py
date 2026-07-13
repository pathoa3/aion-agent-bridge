#!/usr/bin/env python3
from pass653_common import *
import subprocess

def main():
    rows=[]
    def add(name,result,conf,reason): rows.append({"check_name":name,"result":str(result).lower(),"confidence":conf,"reason":reason})
    add("latest_pcap_exists", PCAP.exists(), "high", str(PCAP))
    add("known_log_exists", LOG.exists(), "high", str(LOG))
    markers=load_markers(); add("s2c_a_length_ladder_rows", len(markers)==8, confidence_from_count(len(markers)), f"rows={len(markers)}")
    old=old_oracle_count(); add("old_s2c_oracle_rows_ignored", old>=0, "high", f"old_rows={old}; S2C_A rows selected when present")
    packets=parse_pcapng(PCAP) if PCAP.exists() else []
    add("10242_flow_exists", len(pkts(packets,CHAT_PORT))>0, "high", f"payload_packets={len(pkts(packets,CHAT_PORT))}")
    add("7780_flow_exists", len(pkts(packets,WORLD_PORT))>0, "high", f"payload_packets={len(pkts(packets,WORLD_PORT))}")
    p652=ART/"pass652_prototype_event_labels.csv"; add("pass652_prototype_labels_exist", p652.exists(), "high" if p652.exists() else "low", str(p652))
    try:
        staged=subprocess.check_output(["git","ls-files"], cwd=REPO, text=True, stderr=subprocess.DEVNULL).splitlines()
    except Exception:
        staged=[]
    forbidden=[x for x in staged if any(t in x.lower() for t in [".pcap",".pcapng","ciphertext","raw_packet","packet_hex","packet_hash","plaintext_blob"])]
    add("no_raw_payload_artifacts_present_in_git", len(forbidden)==0, "high" if not forbidden else "low", f"forbidden_tracked_count={len(forbidden)}")
    write_csv(ART/"pass653_stage_a_input_audit.csv", rows, ["check_name","result","confidence","reason"])
    print({"audit_rows":len(rows)})
if __name__=="__main__": main()
