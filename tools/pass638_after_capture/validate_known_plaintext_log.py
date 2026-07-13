#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

REQUIRED_COLUMNS = ["timestamp_local", "frame_hint", "direction", "visible_text", "notes"]
MARKER_RE = re.compile(r"^[ -~]{16,}$")


def sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        return csv.excel


def load_rows(path: Path) -> tuple[list[dict], list[str], str]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    sample = "\n".join(text.splitlines()[:8])
    dialect = sniff_dialect(sample)
    reader = csv.DictReader(text.splitlines(), dialect=dialect)
    rows = list(reader)
    fields = list(reader.fieldnames or [])
    return rows, fields, getattr(dialect, "delimiter", ",")


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate S2C known plaintext log without emitting payload data.")
    ap.add_argument("log_path", type=Path)
    ap.add_argument("--out-csv", type=Path, default=Path("artifacts/pass638_known_plaintext_log_status.csv"))
    ap.add_argument("--out-json", type=Path, default=None)
    ns = ap.parse_args()

    checks: list[dict[str, str]] = []

    def add(check: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": check, "ok": str(ok).lower(), "detail": detail})

    if not ns.log_path.exists():
        add("log_exists", False, str(ns.log_path))
        rows: list[dict] = []
        fields: list[str] = []
        delimiter = ""
    else:
        add("log_exists", True, str(ns.log_path))
        try:
            rows, fields, delimiter = load_rows(ns.log_path)
            add("csv_parse", True, f"rows={len(rows)} delimiter={delimiter!r}")
        except Exception as exc:
            rows, fields, delimiter = [], [], ""
            add("csv_parse", False, type(exc).__name__)

    missing = [c for c in REQUIRED_COLUMNS if c not in fields]
    add("required_columns", not missing, ";".join(missing))

    visible = [(r.get("visible_text") or "").strip() for r in rows]
    directions = [(r.get("direction") or "").strip().upper() for r in rows]
    nonempty = [v for v in visible if v]
    marker_rows = [v for v, d in zip(visible, directions) if v and d == "S2C"]
    counts = {v: marker_rows.count(v) for v in set(marker_rows)}
    repeated = sorted([v for v, c in counts.items() if c >= 2])
    short = [v for v in marker_rows if not MARKER_RE.match(v)]
    bad_dir = [d for d, v in zip(directions, visible) if v and d != "S2C"]

    add("no_empty_visible_text", len(nonempty) == len(rows) and len(rows) > 0, f"rows={len(rows)} nonempty={len(nonempty)}")
    add("oracle_rows_are_s2c", len(bad_dir) == 0 and len(marker_rows) > 0, f"bad_direction_rows={len(bad_dir)} s2c_rows={len(marker_rows)}")
    add("markers_at_least_16_ascii", len(short) == 0 and len(marker_rows) > 0, f"short_or_non_ascii={len(short)}")
    add("repeated_marker_exists", len(repeated) > 0, f"repeat_count={len(repeated)}")

    ok = all(row["ok"] == "true" for row in checks)
    add("overall_ready", ok, "safe metadata only")

    ns.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with ns.out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "ok", "detail"])
        writer.writeheader()
        writer.writerows(checks)

    if ns.out_json:
        ns.out_json.parent.mkdir(parents=True, exist_ok=True)
        ns.out_json.write_text(json.dumps({"ok": ok, "rows": len(rows), "checks": checks}, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({"ok": ok, "rows": len(rows), "out_csv": str(ns.out_csv)}, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
