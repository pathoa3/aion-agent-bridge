"""Summarize Pass620 S2C key setup candidates and write final artifacts."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from trace_s2c_key_setup_static import run_trace
from find_s2c_key_artifacts import ARTIFACTS, REPO


def choose_best(candidates: list[dict[str, str]]) -> dict[str, str]:
    for pref in ["CTX-002", "CTX-001"]:
        for c in candidates:
            if c.get("candidate_id") == pref:
                return c
    return candidates[0] if candidates else {
        "candidate_id": "none",
        "possible_role": "no candidate",
        "confidence": "none",
        "next_test": "manual review",
    }


def write_summary(hits: list[dict[str, str]], candidates: list[dict[str, str]], decision: dict[str, object]) -> None:
    best = choose_best(candidates)
    summary = f"""# Pass620 Codex S2C Key Setup Static Trace\n\n## Result\n\nS2C initial key found: **no**.\n\nThis pass performed a narrow static/offline trace over the requested summaries, reports, Pass616/617/618 tool text, `EA_VM_TargetDumpJava.java`, and existing safe VM/static export summaries. It did not rerun C2S work, did not run broad PCAP brute force, and did not modify working C2S tools.\n\n## Best Candidate\n\n- Candidate: `{best.get('candidate_id')}`\n- Role: {best.get('possible_role')}\n- Confidence: {best.get('confidence')}\n- Next test: {best.get('next_test')}\n\n## Findings\n\n- C2S/S2C context split: **implied but not structurally located**. The solved C2S path and failed S2C probe indicate shared transform logic with independent initial key state.\n- Handshake seed derivation path: **not found** as a concrete assignment/write path. Pass618 states this is the likely source, but the available text artifacts do not expose the native/VM write into the S2C key slot.\n- Static search hits written: `{len(hits)}` Git-safe rows.\n- Candidate rows written: `{len(candidates)}`.\n- Bounded S2C validation: **not run**, because no concrete candidate initial key or derivation rule was found.\n\n## Blocker\n\nThe remaining blocker is a missing file-backed trace from the world/server handshake receive path to the S2C rolling key initialization field. PCAP-only search is exhausted for this purpose; the next useful work is targeted static tracing of receive-path key setup.\n\n## Next Action\n\nTrace native/VM static exports for the 7785 receive/world-handshake path until a concrete assignment to an S2C 8-byte rolling key slot is found, or generate a more focused static export around recv/decode handshake call sites.\n"""
    (ARTIFACTS / "pass620_codex_s2c_key_setup_summary.md").write_text(summary, encoding="utf-8")


def main() -> dict[str, object]:
    hits, candidates = run_trace()
    best = choose_best(candidates)
    decision = {
        "worker": "codex",
        "phase": "pass620_s2c_key_setup_static_trace",
        "s2c_initial_key_found": False,
        "s2c_key_candidates_count": len(candidates),
        "best_candidate_id": best.get("candidate_id", "none"),
        "c2s_s2c_context_split_found": False,
        "handshake_seed_derivation_path_found": False,
        "bounded_s2c_validation_run": False,
        "s2c_packets_decoded_sequentially": 0,
        "first_divergence_frame": None,
        "s2c_decoder_success": False,
        "c2s_tools_modified": False,
        "sonnet_files_modified": False,
        "antigravity_files_modified": False,
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Narrow static trace found shared C2S/S2C transform evidence and handshake-seed references, but no concrete file-backed assignment of an S2C initial key or server seed into an S2C rolling key slot.",
        "next_action": "targeted static trace of world/7785 receive handshake path to S2C 8-byte key state assignment",
    }
    (ARTIFACTS / "pass620_codex_s2c_key_setup_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    write_summary(hits, candidates, decision)
    report = f"""# Codex Report - Pass620 S2C Key Setup Static Trace\n\n- S2C initial key found: false\n- Best candidate: {best.get('candidate_id')}\n- Evidence: {best.get('possible_role')}\n- C2S/S2C context split found: false, only implied by shared transform plus independent initial key state\n- Handshake seed derivation path found: false\n- Bounded validation run: false\n- First divergence frame: null\n- S2C decoder success: false\n- Next action: targeted static trace of world/7785 receive handshake path to S2C 8-byte key state assignment\n- Safety: no C2S tool changes, no Sonnet/Antigravity file changes, no private packet or raw binary data committed.\n"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
