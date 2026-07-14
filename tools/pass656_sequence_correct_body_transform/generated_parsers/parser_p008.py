#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"tools"/"pass656_sequence_correct_body_transform"))
from pass656_common import *
MODEL={'model_id': 'fm03410', 'header_size': '16', 'length_field_offset': '8', 'length_width': '1', 'endianness': 'little', 'frames': '1180', 'coverage': '1.0', 'invalid_lengths': '3', 'resync_distance': '3', 'arbitrary_target_size_used': 'false', 'survives': 'true', 'score': '91.77', 'confidence': 'medium', 'reason': 'deterministic first-plausible length arithmetic; no nearest-target heuristic', 'parser_id': 'p008'}; BODY={'body_model_id': 'bm0008', 'frame_model_id': 'fm03410', 'body_start': '15', 'trailer_len': '2', 'frames_sampled': '197', 'mean_entropy': '5.547', 'repeat_stability': 'unknown_pending_transform', 'channel_pair_signal': 'metadata_only', 'length_ladder_consistency': 'metadata_only', 'score': '18.943', 'survives': 'true', 'confidence': 'medium', 'reason': 'bounded body boundary grid around header/length candidates; score is evidence only'}
if __name__=="__main__":
    segs=parse_pcapng_seq(PCAP); world=detect_world(segs); data,_,_=reassemble_by_seq(flow(segs,world,"S2C")); frames,_=split_frames(data,MODEL)
    total=hits=0
    for o in oracles():
        for a,b,h,sz in frames[:500]:
            bs=a+int(BODY["body_start"]); be=max(bs,b-int(BODY["trailer_len"]))
            if be<=bs: continue
            body=data[bs:be]
            for _n,tdata in transform_variants(body,o["visible_text"]):
                total+=1
                if contains_exact_message(tdata,o): hits+=1
    print("parser_id,oracle_rows,tests,exact_hits")
    print(f"{MODEL['parser_id']},17,{total},{hits}")
