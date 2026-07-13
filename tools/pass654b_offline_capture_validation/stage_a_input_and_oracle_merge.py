#!/usr/bin/env python3
from common import *
def main():
    rows=[]
    for r in merged_oracles():
        rows.append({k:r.get(k,"") for k in ["oracle_id","source","channel","speaker","visible_text","text_length","app_time","logged_time","chosen_time","time_tolerance_ms","current_capture","strong_reference","reason"]})
    write_csv(ART/"pass654b_oracle_rows.csv", rows, ["oracle_id","source","channel","speaker","visible_text","text_length","app_time","logged_time","chosen_time","time_tolerance_ms","current_capture","strong_reference","reason"])
    print({"oracle_rows":len(rows)})
if __name__=="__main__": main()
