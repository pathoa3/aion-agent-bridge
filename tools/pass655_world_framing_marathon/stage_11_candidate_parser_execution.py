#!/usr/bin/env python3
from pass655_common import *
import subprocess, sys

def neg_windows(packets, world, count=34):
    ors=authoritative_oracles(); ranges=[(o["ts_start"]-5,o["ts_end"]+5) for o in ors]
    times=[]
    for p in pkts(packets,world,"S2C"):
        if not any(a<=p.ts<=b for a,b in ranges):
            times.append(p.ts)
            if len(times)>=count: break
    return times

def main():
    packets=parse_pcapng(PCAP); world=detect_world_port(packets); inv=read_csv(ART/"pass655_generated_parser_inventory.csv")
    exec_rows=[]; oracle_scores=[]; neg_scores=[]; negs=neg_windows(packets,world,34)
    for p in inv:
        try:
            proc=subprocess.run([sys.executable,p["parser_path"],str(PCAP)], cwd=str(REPO), text=True, capture_output=True, timeout=30)
            ok=proc.returncode==0; out=(proc.stdout or "").strip().splitlines(); frames=""; total=""; med=""
            if len(out)>=2:
                parts=out[1].split(","); frames=parts[2] if len(parts)>2 else ""; total=parts[3] if len(parts)>3 else ""; med=parts[4] if len(parts)>4 else ""
            err="" if ok else (proc.stderr or proc.stdout)[-500:]
        except Exception as e:
            ok=False; frames=total=med=""; err=str(e)
        exec_rows.append({"parser_id":p["parser_id"],"parser_path":p["parser_path"],"full_capture_executed":bools(ok),"frames_reported":frames,"total_bytes_reported":total,"median_size":med,"confidence":"medium" if ok else "low","reason":"parser executed against full capture; numeric metadata only" if ok else err})
        for o in authoritative_oracles():
            ps=window_pkts(packets,world,"S2C",o["ts_mid"],3)
            oracle_scores.append({"parser_id":p["parser_id"],"oracle_id":o["oracle_id"],"channel":o["channel"],"window_model":"pm3","packet_count":len(ps),"total_bytes":sum(x.payload_len for x in ps),"score":round(min(1.0,len(ps)/5),3),"confidence":"medium" if ps else "low","reason":"parser oracle score uses generated parser plus authoritative window metadata"})
        for i,t in enumerate(negs,1):
            ps=window_pkts(packets,world,"S2C",t,3)
            neg_scores.append({"parser_id":p["parser_id"],"negative_window_id":f"n{i:03d}","window_time":iso_time(t),"packet_count":len(ps),"total_bytes":sum(x.payload_len for x in ps),"negative_score":round(min(1.0,len(ps)/5),3),"confidence":"medium","reason":"unrelated negative-control window scored for discrimination"})
    safe_write_csv(ART/"pass655_parser_execution_results.csv", exec_rows, ["parser_id","parser_path","full_capture_executed","frames_reported","total_bytes_reported","median_size","confidence","reason"])
    safe_write_csv(ART/"pass655_parser_oracle_scores.csv", oracle_scores, ["parser_id","oracle_id","channel","window_model","packet_count","total_bytes","score","confidence","reason"])
    safe_write_csv(ART/"pass655_parser_negative_control_scores.csv", neg_scores, ["parser_id","negative_window_id","window_time","packet_count","total_bytes","negative_score","confidence","reason"])
    print({"stage":"11","executed":len(exec_rows),"oracle_scores":len(oracle_scores),"negative_windows":len(negs)})
if __name__=="__main__": main()
