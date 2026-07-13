#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
from pathlib import Path

CAPTURE = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng")
LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
REPO = Path(r"C:\AionTools\aion-agent-bridge")
MARKERS = [
    "S2C_ORACLE_001_A1B2",
    "S2C_ORACLE_002_C3D4",
    "S2C_ORACLE_003_0123456789",
    "S2C_ORACLE_004_REPEAT",
]

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=str(REPO))
    ns = ap.parse_args()
    rows = []
    text = LOG.read_text(encoding="utf-8", errors="replace") if LOG.exists() else ""
    marker_hits = {m: text.count(m) for m in MARKERS}
    rows.append({"check": "capture_exists", "ok": str(CAPTURE.exists()).lower(), "detail": str(CAPTURE)})
    rows.append({"check": "capture_nonempty", "ok": str(CAPTURE.exists() and CAPTURE.stat().st_size > 24).lower(), "detail": str(CAPTURE.stat().st_size if CAPTURE.exists() else 0)})
    rows.append({"check": "known_plaintext_log_exists", "ok": str(LOG.exists()).lower(), "detail": str(LOG)})
    for marker, count in marker_hits.items():
        rows.append({"check": f"marker_present_{marker}", "ok": str(count > 0).lower(), "detail": str(count)})
    out = Path(ns.repo_root) / "artifacts" / "pass637_capture_kit_status.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["check", "ok", "detail"])
        w.writeheader(); w.writerows(rows)
    print({"capture_exists": CAPTURE.exists(), "log_exists": LOG.exists(), "status_csv": str(out)})

if __name__ == "__main__":
    main()
