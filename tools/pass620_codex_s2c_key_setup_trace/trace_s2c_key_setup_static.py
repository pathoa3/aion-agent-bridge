"""Trace S2C key setup from narrow static search hits."""
from __future__ import annotations

import csv
from pathlib import Path
from find_s2c_key_artifacts import ARTIFACTS, LOCAL_OUT, find_hits, write_hits
from compare_c2s_s2c_context_layout import compare, write_notes


def build_candidates(hits: list[dict[str, str]]) -> list[dict[str, str]]:
    candidates = compare()
    seed_terms = {"server seed", "world server seed", "handshake", "SM_KEY", "2106", "39 90 C5 A2", "73 5A 12 08", "2D 66 BD 65"}
    direction_terms = {"S2C", "server-to-client", "recv", "decode"}
    key_terms = {"rolling key", "session key", "STATIC_KEY", "decrypt", "encrypt"}
    cid = 4
    seen_roles = set()
    for h in hits:
        term = h["term"]
        ctx = h["short_context"]
        source = h["source_file"]
        src_low = source.lower()
        # Planning handovers are useful in the raw hit table, but candidate rows
        # should prioritize source/tool/static-export evidence.
        if "pass619_codex_s2c_next_task" in src_low:
            continue
        if term in seed_terms or any(s.lower() in ctx.lower() for s in ["seed", "handshake", "sm_key"]):
            role = "handshake/seed reference; may identify S2C initial-key setup but no assignment target is proven"
            et = "seed_derivation_candidate"
            conf = "medium" if "pass618" in source.lower() or "sonnet_report" in source.lower() else "low"
        elif term in direction_terms:
            role = "direction-specific S2C/recv/decode reference; useful for routing static trace"
            et = "direction_split_candidate"
            conf = "medium" if "pass618" in source.lower() or "tools" in source.lower() else "low"
        elif term in key_terms:
            role = "cipher/key routine reference; likely shared transform rather than initial-key source"
            et = "packet_setup_candidate"
            conf = "medium"
        elif term in {"4e99ca25", "a16c5487", "0xA16C5487"}:
            role = "invalidated checkpoint key negative control"
            et = "negative_control"
            conf = "high"
        else:
            continue
        key = (source, term, role)
        if key in seen_roles:
            continue
        seen_roles.add(key)
        candidates.append({
            "candidate_id": f"S2C-{cid:03d}",
            "source_file": source,
            "location": h["location"],
            "evidence_type": et,
            "possible_role": role,
            "confidence": conf,
            "next_test": "static trace to concrete assignment/write into S2C key slot" if et != "negative_control" else "exclude from candidate keys",
        })
        cid += 1
        if cid > 24:
            break
    return candidates


def write_candidates(candidates: list[dict[str, str]]) -> None:
    fields = ["candidate_id", "source_file", "location", "evidence_type", "possible_role", "confidence", "next_test"]
    with (ARTIFACTS / "pass620_codex_s2c_key_candidates.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(candidates)
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    with (LOCAL_OUT / "detailed_candidates_local.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(candidates)


def run_trace() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    hits = find_hits()
    write_hits(hits)
    write_notes()
    candidates = build_candidates(hits)
    write_candidates(candidates)
    return hits, candidates


if __name__ == "__main__":
    h, c = run_trace()
    print(f"hits={len(h)} candidates={len(c)}")

