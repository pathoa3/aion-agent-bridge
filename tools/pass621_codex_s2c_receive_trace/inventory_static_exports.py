"""Pass621 static export inventory.

Inventories actual static export/decompile/p-code/flow files only. It avoids
binary contents and does not use Pass616-Pass620 summaries as proof.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

REPO = Path(r"C:\AionTools\aion-agent-bridge")
ARTIFACTS = REPO / "artifacts"
PRIVATE = Path(r"C:\AionTools\aion_decoder_agent")

ROOTS = [
    Path(r"C:\AionTools"),
    PRIVATE,
    REPO,
]

NAME_RE = re.compile(r"(ghidra|pcode|disasm|disassembly|flow|handler|pass8b|pass8c|targetdump|ea_vm|vm[_-]?table|decompile)", re.I)
TERMS = ["0x11B562BD", "11B562BD", "11b562bd", "0x11B5630F", "11B5630F", "11b5630f", "0x11B5932F", "11B5932F", "11b5932f", "0x11B57796", "11B57796", "11b57796", "0x11B55DF6", "11B55DF6", "11b55df6"]
TEXT_EXTS = {".txt", ".csv", ".md", ".json", ".java", ".py"}
SKIP_PARTS = {".git", "__pycache__", "site-packages", "compiled-bundles", "ghidra_appdata", "ghidra_localappdata"}


def relevant_file(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & SKIP_PARTS:
        return False
    if path.suffix.lower() not in TEXT_EXTS:
        return False
    return bool(NAME_RE.search(path.name)) or "pass8b" in path.name.lower() or "pass8c" in path.name.lower()


def iter_files() -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for root in ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or not relevant_file(path):
                continue
            key = str(path.resolve()).lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
    return sorted(out, key=lambda p: str(p).lower())


def content_terms(path: Path) -> list[str]:
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    found = []
    low = txt.lower()
    for term in TERMS:
        if term.lower() in low and term.upper().replace("0X", "0x") not in found:
            found.append(term)
    for term in ["recv", "receive", "handshake", "SM_KEY", "7785", "2106", "server", "client", "key", "R12", "RSI", "RBP"]:
        if term.lower() in low:
            found.append(term)
    return found


def relevance(path: Path, terms: list[str]) -> tuple[str, str]:
    name = path.name.lower()
    if "pass8b_target_pcode" in name or "pass8b_target_disassembly" in name or "pass8b_target_flows" in name:
        return "high", "primary Ghidra target export covering dispatcher/handler slices"
    if "pass8c_recursive" in name or "pass8c_flow" in name or "interesting_state" in name:
        return "high", "recursive Ghidra flow export covering VM launch/dispatcher state"
    if "handler_table" in name:
        return "high", "VM opcode-to-handler table export"
    if path.name in {"EA_VM_TargetDumpJava.java", "EA_VM_FlowDumpJava.java"}:
        return "medium", "Ghidra export script, not result data"
    if terms:
        return "medium", "text export with requested address/key terms"
    return "low", "static text file matching export naming pattern"


def build_inventory() -> list[dict[str, str]]:
    rows = []
    for path in iter_files():
        terms = content_terms(path)
        rel, notes = relevance(path, terms)
        rows.append({
            "path": str(path),
            "file_size": str(path.stat().st_size),
            "matched_terms": ";".join(sorted(set(terms), key=str.lower)),
            "relevance": rel,
            "notes": notes,
        })
    return rows


def write_inventory(rows: list[dict[str, str]]) -> None:
    fields = ["path", "file_size", "matched_terms", "relevance", "notes"]
    with (ARTIFACTS / "pass621_codex_static_export_inventory.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    rows = build_inventory()
    write_inventory(rows)
    print(f"exports={len(rows)}")
