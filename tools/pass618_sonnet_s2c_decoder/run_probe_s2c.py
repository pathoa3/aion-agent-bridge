"""
run_probe_s2c.py
================
CLI runner for the S2C world stream probe.

Phases:
  1. Build S2C packet inventory from the PCAP.
  2. Test bounded anchor candidates.
  3. Attempt sequential S2C key rolling.

Usage:
    python run_probe_s2c.py [path/to/capture.pcapng]
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from euroaion_s2c_probe import (
    ANCHOR_FRAME,
    extract_s2c_packets,
    build_inventory,
    search_anchor_candidates,
    attempt_s2c_rolling,
)

DEFAULT_PCAP = Path(
    r"C:\AionTools\aion_decoder_agent\inbox\captures\startup_world_open_kxseq.pcapng"
)
OUTBOX = Path(
    r"C:\AionTools\aion_decoder_agent\outbox\pass618_sonnet_s2c_decoder_local"
)


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    if not pcap.exists():
        print(f"ERROR: capture not found: {pcap}")
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()
    print(f"EuroAion S2C World Stream Probe")
    print(f"Capture: {pcap.name}")
    print(f"Run at : {now}")
    print()

    # ── Phase 1: Inventory ────────────────────────────────────────────────────
    print("=== Phase 1: S2C Packet Inventory ===")
    s2c_pkts = extract_s2c_packets(pcap, ANCHOR_FRAME)
    inventory = build_inventory(s2c_pkts)
    total      = len(inventory)
    bulk_count = sum(1 for r in inventory if r["is_bulk"] == "yes")
    small_count= total - bulk_count
    print(f"  Total S2C packets : {total}")
    print(f"  Bulk (>=1000 B)   : {bulk_count}")
    print(f"  Small (<1000 B)   : {small_count}")
    print()

    OUTBOX.mkdir(parents=True, exist_ok=True)
    inv_path = OUTBOX / "s2c_inventory_full.csv"
    with inv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["index", "frame", "payload_len", "body_len", "is_bulk"])
        w.writeheader()
        w.writerows(inventory)
    print(f"  Inventory written: {inv_path}")
    print()

    # ── Phase 2: Anchor candidates ────────────────────────────────────────────
    print("=== Phase 2: Anchor Candidate Search ===")
    candidates, hit_count = search_anchor_candidates(s2c_pkts)
    print(f"  Candidates tested : {len(candidates)}")
    print(f"  Low-opcode hits   : {hit_count}")
    anchor_found = any(c.get("valid_header") == "yes" and c.get("confidence") == "high"
                       for c in candidates)
    print(f"  Anchor confirmed  : {'YES' if anchor_found else 'NO'}")
    print()
    print("  Per-candidate results (checkpoint key test):")
    for c in candidates[:3]:
        print(f"    frame={c['frame']}  label={c['label']}  "
              f"valid={c['valid_header']}  op={c.get('opcode_candidate','?')}  "
              f"comp={c['complement_ok']}  confidence={c['confidence']}")
    print()

    cand_path = OUTBOX / "s2c_candidate_trials_full.csv"
    with cand_path.open("w", encoding="utf-8", newline="") as f:
        fields = ["candidate_id", "frame", "label", "seed_or_key_source",
                  "header_rule_tested", "valid_header", "opcode_candidate",
                  "complement_ok", "confidence", "reason", "next_step"]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(candidates)
    print(f"  Candidates written: {cand_path}")
    print()

    # ── Phase 3: Rolling attempt ──────────────────────────────────────────────
    print("=== Phase 3: Sequential S2C Rolling ===")
    roll = attempt_s2c_rolling(s2c_pkts, max_steps=8)
    print(f"  Anchor frame      : {roll['anchor_frame']}")
    for t in roll["trace"]:
        cap = " (CAPPED)" if t["capped"] else ""
        print(f"  step={t['step']:2}  frame={t['frame']}  plen={t['plen']:4}  "
              f"paths={t['paths']}{cap}")
    print()
    print(f"  First dead frame  : {roll.get('first_dead_frame', 'none')}")
    print(f"  Final path count  : {roll.get('final_path_count', '?')}")
    print(f"  Ambiguous         : {roll.get('ambiguous', '?')}")
    print()
    print(f"  Blocker:")
    print(f"    {roll.get('blocker', 'unknown')}")
    print()

    trace_path = OUTBOX / "s2c_keyroll_trace_local.csv"
    with trace_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["step", "frame", "plen", "paths", "capped"])
        w.writeheader()
        w.writerows(roll["trace"])
    print(f"  Trace written: {trace_path}")
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print("=" * 60)
    print(f"S2C inventory built  : yes")
    print(f"S2C packets indexed  : {total}")
    print(f"Anchor candidates    : {len(candidates)}")
    print(f"Anchor found         : {'yes' if anchor_found else 'no'}")
    print(f"Sequentially decoded : 1 (anchor frame only)")
    print(f"First divergence     : {roll.get('first_dead_frame', 'n/a')}")
    print(f"S2C decoder success  : no")
    print(f"Best blocker         : S2C initial key unknown (derived from server "
          f"handshake seed not available from static PCAP analysis alone)")
    print()
    print(f"Local output: {OUTBOX}")


if __name__ == "__main__":
    main()
