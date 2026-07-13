from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

DEFAULT_REPO = Path(__file__).resolve().parents[2]
DEFAULT_LOG = Path(r"C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt")
DEFAULT_OUT = DEFAULT_REPO / "artifacts" / "pass638_known_plaintext_log_status.csv"


def is_ascii(text: str) -> bool:
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def classify_row(direction: str, visible_text: str, notes: str) -> tuple[str, bool, str]:
    text = (visible_text or "").strip()
    notes_l = (notes or "").lower()
    direction_u = (direction or "").upper()
    warnings = []
    if not is_ascii(text):
        warnings.append("non_ascii_visible_text")
    if len(text) < 16:
        warnings.append("short_visible_text")
    if text == "/ping" or "ping function" in notes_l:
        return "non_chat_metadata", False, ";".join(warnings + ["not_chat_oracle"])
    if direction_u == "S2C" and len(text) >= 16 and is_ascii(text) and text.startswith("S2C_ORACLE_"):
        return "strong_s2c_oracle", True, ";".join(warnings)
    return "weak_text_candidate", False, ";".join(warnings + ["not_strong_s2c_oracle"])


def validate(log_path: Path, output_path: Path) -> dict:
    rows_out = []
    with log_path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            row_class, usable, warning = classify_row(row.get("direction", ""), row.get("visible_text", ""), row.get("notes", ""))
            rows_out.append({
                "row_index": i,
                "timestamp_local": row.get("timestamp_local", ""),
                "frame_hint": row.get("frame_hint", ""),
                "visible_text": row.get("visible_text", ""),
                "direction": row.get("direction", ""),
                "notes": row.get("notes", ""),
                "row_class": row_class,
                "usable_for_s2c_oracle": str(bool(usable)).lower(),
                "warning": warning,
            })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        fields = ["row_index", "timestamp_local", "frame_hint", "visible_text", "direction", "notes", "row_class", "usable_for_s2c_oracle", "warning"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows_out)
    classes = Counter(r["row_class"] for r in rows_out)
    strong_texts = [r["visible_text"] for r in rows_out if r["row_class"] == "strong_s2c_oracle"]
    repeated = any(count > 1 for count in Counter(strong_texts).values())
    return {
        "rows": len(rows_out),
        "strong_s2c_oracle_rows": classes.get("strong_s2c_oracle", 0),
        "weak_text_rows": classes.get("weak_text_candidate", 0),
        "non_chat_rows": classes.get("non_chat_metadata", 0),
        "repeated_strong_marker": repeated,
        "overall_ready": classes.get("strong_s2c_oracle", 0) >= 3 and repeated,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and classify known plaintext log rows without blocking on weak rows.")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    summary = validate(args.log, args.out)
    print("known_plaintext_log " + " ".join(f"{k}={v}" for k, v in summary.items()))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

