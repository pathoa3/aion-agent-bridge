"""Compare solved C2S context evidence against S2C blocker evidence."""
from __future__ import annotations

from pathlib import Path
import csv

REPO = Path(r"C:\AionTools\aion-agent-bridge")
ARTIFACTS = REPO / "artifacts"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def compare() -> list[dict[str, str]]:
    c2s = read(ARTIFACTS / "pass616_sonnet_c2s_decoder_summary.md")
    s2c = read(ARTIFACTS / "pass618_sonnet_s2c_decoder_summary.md")
    rows = [
        {
            "candidate_id": "CTX-001",
            "source_file": "pass616/pass618 summaries",
            "location": "algorithm sections",
            "evidence_type": "context_layout_candidate",
            "possible_role": "C2S and S2C appear to use same stream/key-roll formula but independent initial key state",
            "confidence": "high",
            "next_test": "trace direction-specific initial key assignment, not cipher formula",
        },
        {
            "candidate_id": "CTX-002",
            "source_file": "pass618_sonnet_s2c_decoder_summary.md",
            "location": "Root cause",
            "evidence_type": "seed_derivation_candidate",
            "possible_role": "S2C initial key is session-derived from encrypted world-server handshake seed",
            "confidence": "medium",
            "next_test": "static trace handshake seed extraction/assignment into recv/S2C key slot",
        },
        {
            "candidate_id": "CTX-003",
            "source_file": "pass618_sonnet_s2c_anchor_candidates.csv",
            "location": "checkpoint rows",
            "evidence_type": "negative_control",
            "possible_role": "checkpoint key 4e99ca25a16c5487 invalidated; must not be reused as evidence",
            "confidence": "high",
            "next_test": "exclude checkpoint key from validation unless new static evidence reintroduces it",
        },
    ]
    return rows


def write_notes() -> None:
    notes = """# Pass620 Codex S2C Context Layout Notes\n\n## C2S Solved Context\n\nPass616/617 establish that C2S decoding works with the `STATIC_KEY` XOR rolling stream, opcode complement validation, and linear/VM key-roll family. The C2S tools are treated as read-only evidence in this pass.\n\n## S2C Comparison\n\nPass618 indicates S2C likely uses the same cipher formula and key-roll family, but not the same initial key. Static PCAP-only analysis leaves many valid single-frame candidates and explodes through bulk frames, so the missing object is the S2C initial key or its handshake-derived seed.\n\n## Context Split Assessment\n\nA direction split is strongly implied at the state level: C2S and S2C share transform logic but require independent initial key state. This pass did not find a concrete file-backed struct offset for two adjacent 8-byte key slots. The next static trace should therefore target receive/world-handshake setup code rather than the already-solved stream transform.\n\n## Practical Next Trace\n\nSearch native/VM static exports for call sites that route 7785 receive packets, decrypt or parse the server handshake/SM_KEY, and assign an 8-byte rolling key state used by S2C decode.\n"""
    (ARTIFACTS / "pass620_codex_s2c_context_layout_notes.md").write_text(notes, encoding="utf-8")


if __name__ == "__main__":
    write_notes()
    for row in compare():
        print(row)
