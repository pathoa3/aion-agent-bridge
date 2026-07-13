#!/usr/bin/env python3
from common import *
def compression_probe(data, needle):
    if not data or not needle: return False
    tries=[]
    if data[:2] in (b"\x78\x01",b"\x78\x9c",b"\x78\xda"): tries.append(lambda d:zlib.decompress(d))
    if data[:2]==b"\x1f\x8b": tries.append(lambda d:gzip.decompress(d))
    for fn in tries:
        try:
            if fn(data).find(needle)>=0: return True
        except Exception: pass
    return False

def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); rows=[]; findings=[]; tid=1; fid=1
    flows=[(world,"world"),(SIDE_PORT,"event_side")]
    for o in [x for x in merged_oracles() if x["current_capture"]]:
        for port,role in flows:
            if port is None: continue
            for direction in ("S2C","C2S"):
                for win_name,sec in [("nearest",0),("pm1",1),("pm3",3),("pm5",5),("pm10",10)]:
                    if sec==0:
                        n=nearest(pkts(packets,port,direction),o["ts"]); data=n.payload if n else b""; frame=n.frame if n else ""
                    else:
                        data=bytes_for_window(packets,port,direction,o["ts"],sec); frame=win_name
                    for rep,needle in reps(o["visible_text"],o["speaker"],o["channel"]):
                        hit=find_rep(data,needle); ch=o["channel"].lower(); sender=o["speaker"]
                        exact_msg=hit and rep in ("ascii","utf16le","utf16be","nul_ascii","no_underscore") and o["visible_text"].startswith("S2C")
                        sender_hit=hit and sender and ("token" in rep and sender[:6] in rep)
                        channel_hit=hit and ch in rep.lower()
                        rows.append({"test_id":f"t{tid:05d}","oracle_id":o["oracle_id"],"channel":o["channel"],"flow_role":role,"server_port":port,"direction":direction,"window_model":win_name,"representation":rep,"header_offset":"0-32","segments_spanned":str(sec!=0).lower(),"tests_run":1,"hits":1 if hit else 0,"exact_message_match":bools(exact_msg),"exact_sender_match":bools(sender_hit),"exact_channel_match":bools(channel_hit),"repeat_consistent":"pending","confidence":"high" if exact_msg else "medium" if hit else "low","reason":"deterministic local byte search; metadata only"}); tid+=1
                        if hit:
                            findings.append({"finding_id":f"f{fid:04d}","oracle_id":o["oracle_id"],"flow_role":role,"server_port":port,"direction":direction,"representation":rep,"frame_or_window":frame,"exact_message_match":bools(exact_msg),"exact_sender_match":bools(sender_hit),"exact_channel_match":bools(channel_hit),"local_detail_path":"","confidence":"high" if exact_msg else "medium","reason":"hit metadata only; no bytes written"}); fid+=1
    # repeat consistency pass by exact text/representation/flow/direction
    buckets=defaultdict(list)
    for r in rows:
        if r["hits"]==1: buckets[(r["flow_role"],r["direction"],r["representation"],r["channel"])].append(r)
    for r in rows:
        key=(r["flow_role"],r["direction"],r["representation"],r["channel"]); r["repeat_consistent"]=bools(len(buckets.get(key,[]))>=2)
    write_csv(ART/"pass654b_known_text_tests.csv", rows, ["test_id","oracle_id","channel","flow_role","server_port","direction","window_model","representation","header_offset","segments_spanned","tests_run","hits","exact_message_match","exact_sender_match","exact_channel_match","repeat_consistent","confidence","reason"])
    write_csv(ART/"pass654b_text_finding_metadata.csv", findings, ["finding_id","oracle_id","flow_role","server_port","direction","representation","frame_or_window","exact_message_match","exact_sender_match","exact_channel_match","local_detail_path","confidence","reason"])
    print({"text_tests":len(rows),"findings":len(findings)})
if __name__=="__main__": main()
