"""Narrow Pass620 static artifact search for S2C key setup evidence.

Searches only selected text artifacts/tool source/static exports. Does not read
PCAP payloads, does not execute target binaries, and sanitizes contexts before
writing Git-safe outputs.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")
ARTIFACTS = REPO / "artifacts"
LOCAL_OUT = PRIVATE / "outbox" / "pass620_codex_s2c_key_setup_trace_local"

SEARCH_FILES = [
    ARTIFACTS / "pass619_codex_s2c_next_task.md",
    ARTIFACTS / "pass619_codex_s2c_next_task_decision.json",
    ARTIFACTS / "pass618_sonnet_s2c_decoder_decision.json",
    ARTIFACTS / "pass618_sonnet_s2c_decoder_summary.md",
    ARTIFACTS / "pass618_sonnet_s2c_anchor_candidates.csv",
    ARTIFACTS / "pass616_sonnet_c2s_decoder_summary.md",
    ARTIFACTS / "pass617_sonnet_c2s_chat_extractor_summary.md",
    REPO / "inbox" / "codex_report.md",
    REPO / "inbox" / "sonnet_report.md",
    Path(r"C:\AionTools\EA_VM_TargetDumpJava.java"),
]

SEARCH_DIRS = [
    REPO / "tools" / "pass616_sonnet_c2s_decoder",
    REPO / "tools" / "pass617_sonnet_c2s_chat_extractor",
    REPO / "tools" / "pass618_sonnet_s2c_decoder",
    REPO / "tools" / "pass611_codex_vm_solve",
]

LOCAL_STATIC_EXPORTS = [
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_pcode_launch_state_report.md",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8b" / "pass8b_handler_table_from_ghidra.md",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_flow_summary.md",
    PRIVATE / "outbox" / "pass611_codex_vm_solve_local" / "ghidra_pass8c" / "pass8c_interesting_state_instructions.csv",
]

TERMS = [
    "S2C", "C2S", "server seed", "world server seed", "handshake", "SM_KEY",
    "session key", "rolling key", "decrypt", "encrypt", "context", "packet",
    "recv", "decode", "server-to-client", "7785", "2106", "STATIC_KEY",
    "19 1A 76 23", "2D 66 BD 65", "39 90 C5 A2", "73 5A 12 08",
    "4e99ca25", "a16c5487", "0xA16C5487",
    "nKO/WctQ0AVLbpzfBkS6NevDYT8ourG5CRlmdjyJ72aswx4EPq1UgZhFMXH?3iI9",
]

RAW_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}\s+){8,}[0-9a-fA-F]{2}\b")
LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def iter_files() -> list[Path]:
    files: list[Path] = []
    for f in SEARCH_FILES + LOCAL_STATIC_EXPORTS:
        if f.exists() and f.is_file():
            files.append(f)
    for d in SEARCH_DIRS:
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.is_file() and f.suffix.lower() in {".py", ".md", ".json", ".csv"}:
                files.append(f)
    seen = set()
    unique = []
    for f in files:
        key = str(f).lower()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sanitize_context(line: str, term: str) -> str:
    s = line.strip().replace("\t", " ")
    s = RAW_HEX_RE.sub("[hex-bytes-redacted]", s)
    s = LONG_HEX_RE.sub("[long-hex-redacted]", s)
    if len(s) > 180:
        idx = s.lower().find(term.lower())
        if idx >= 0:
            start = max(0, idx - 80)
            end = min(len(s), idx + len(term) + 80)
            s = ("..." if start else "") + s[start:end] + ("..." if end < len(line) else "")
        else:
            s = s[:177] + "..."
    return s


def classify(term: str, source: Path, context: str) -> tuple[str, str]:
    t = term.lower()
    c = context.lower()
    if "s2c" in t or "server-to-client" in t or "recv" in t:
        return "direction_split_candidate", "possible S2C/recv path reference"
    if "seed" in t or "handshake" in t or "sm_key" in t or "2106" in t:
        return "seed_derivation_candidate", "possible handshake/seed setup reference"
    if "static_key" in t or "rolling key" in t or "session key" in t or "decrypt" in t or "encrypt" in t:
        return "packet_setup_candidate", "possible cipher/key setup reference"
    if "context" in t or "packet" in t or "7785" in t:
        return "context_layout_candidate", "possible packet context reference"
    if any(x in t for x in ["4e99ca25", "a16c5487", "0xa16c5487"]):
        return "negative_control", "invalidated checkpoint key reference"
    if any(x in t for x in ["2d 66", "39 90", "73 5a", "19 1a"]):
        return "string_reference", "known seed/key value reference"
    return "string_reference", "search term reference"


def find_hits() -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    with (LOCAL_OUT / "full_static_search.log").open("w", encoding="utf-8") as log:
        for path in iter_files():
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception as exc:
                log.write(f"SKIP {path}: {exc}\n")
                continue
            for lineno, line in enumerate(lines, 1):
                low = line.lower()
                for term in TERMS:
                    if term.lower() not in low:
                        continue
                    ctx = sanitize_context(line, term)
                    hit_type, classification = classify(term, path, ctx)
                    row = {
                        "source_file": str(path),
                        "location": str(lineno),
                        "hit_type": hit_type,
                        "term": term,
                        "short_context": ctx,
                        "classification": classification,
                    }
                    hits.append(row)
                    log.write(f"{path}:{lineno}:{term}:{ctx}\n")
    return hits


def write_hits(hits: list[dict[str, str]]) -> None:
    fields = ["source_file", "location", "hit_type", "term", "short_context", "classification"]
    with (ARTIFACTS / "pass620_codex_static_search_hits.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(hits)


if __name__ == "__main__":
    rows = find_hits()
    write_hits(rows)
    print(f"hits={len(rows)}")
