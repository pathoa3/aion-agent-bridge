#!/usr/bin/env python3
from __future__ import annotations

import argparse, csv, json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))


def detect(inv: Path, out_json: Path | None = None) -> dict:
    rows = read_rows(inv)
    worlds = [r for r in rows if r.get("role_guess") == "world_game_candidate"]
    worlds.sort(key=lambda r: (r.get("confidence") == "high", int(r.get("total_tcp_payload_bytes") or 0), float(r.get("duration_sec") or 0)), reverse=True)
    selected = worlds[0] if worlds else None
    old7785 = any(r.get("server_port") == "7785" for r in rows)
    result = {
        "actual_world_port_detected": int(selected["server_port"]) if selected else None,
        "actual_world_flow_id": selected.get("flow_id") if selected else "",
        "old_expected_7785_present": old7785,
        "world_flow_packets": int(selected.get("packets") or 0) if selected else 0,
        "world_flow_total_payload_bytes": int(selected.get("total_tcp_payload_bytes") or 0) if selected else 0,
        "confidence": selected.get("confidence") if selected else "none",
        "reason": selected.get("reason") if selected else "no dynamic 7770-7799 world candidate found",
    }
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", type=Path, default=REPO / "artifacts" / "pass647_broad_flow_inventory.csv")
    ap.add_argument("--out-json", type=Path, default=REPO / "artifacts" / "pass647_world_flow_detection.json")
    ns = ap.parse_args()
    print(json.dumps(detect(ns.inventory, ns.out_json), indent=2))
    return 0

if __name__ == "__main__": raise SystemExit(main())
