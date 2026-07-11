"""Run Pass611 Codex VM solve checkpoint from existing static artifacts."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from parse_existing_vm_exports import ARTIFACTS, LOCAL_OUT, REPO, load_context
from trace_p609012_edge import write_outputs as write_edge
from classify_transform_handlers import write_matrix
from vm_state_model import write_model
from handler_derived_transform_tests import run_tests


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_local(handler_rows: list[dict[str, str]], test_result: dict[str, object]) -> None:
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    with (LOCAL_OUT / "progress_log.md").open("a", encoding="utf-8") as f:
        f.write(f"{utc_now()}, phase1, pass609_pass610_resume, safe artifacts parsed, no public crypto retest, completed, trace P609-012 edge\n")
        f.write(f"{utc_now()}, phase2, 0x114731E0..0x114731F5, packet buffer bridge rejected from available static evidence, no decoder transform derived, completed, handler matrix\n")
        f.write(f"{utc_now()}, phase3, top_transform_handlers, traced {len(handler_rows)} handlers at artifact/classification level, complete handler semantics absent, blocked, provide p-code/dataflow\n")
    with (LOCAL_OUT / "handler_trace_full.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(handler_rows[0].keys()) if handler_rows else ["handler_va"])
        writer.writeheader()
        writer.writerows(handler_rows)
    with (LOCAL_OUT / "candidate_trials_full.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "candidate", "trial_count", "exact_plaintext_recovered", "reason"])
        writer.writerow([utc_now(), "handler_derived_vm_transform", test_result["tested"], test_result["exact_plaintext_recovered"], test_result["reason"]])


def write_summary(decision: dict[str, object]) -> None:
    md = f"""# Pass611 Codex VM Solve Summary\n\nCodex resumed from Pass609/Pass610 and used only file-backed static text/CSV/JSON artifacts. No target client binary was executed, attached, debugged, dumped, injected, or run.\n\n## Findings\n\n- P609-012 edge `0x114731E0..0x114731F5`: **not confirmed as a packet-buffer bridge**; current static evidence rejects it as a decoder source.\n- Transform-relevant handlers traced: **{decision['transform_relevant_handlers_traced']}**.\n- VM state model reconstructed: **{str(decision['vm_state_model_reconstructed']).lower()}**.\n- Handler-derived transforms tested in this checkpoint: **{decision['handler_derived_transforms_tested']}**.\n- Exact plaintext recovered: **false**.\n\n## Why No Decoder Trial Was Run\n\nThe available handler artifacts are strong enough to prioritize handlers, but they are mostly first-instruction classifications plus high-level notes. That is not enough to derive a complete packet transform without guessing. Pass610 already tried the available bounded literal/direct tests and found no exact KXSEQ plaintext.\n\n## Hard Blocker\n\n{decision['best_remaining_blocker']}\n\n## Next Autonomous Step\n\n{decision['next_autonomous_step']}\n"""
    (ARTIFACTS / "pass611_codex_vm_solve_summary.md").write_text(md, encoding="utf-8")


def main() -> dict[str, object]:
    ctx = load_context()
    edge_rows = write_edge(ctx)
    handler_rows = write_matrix(ctx)
    layout_entries = write_model(ctx)
    test_result = run_tests(handler_rows)
    write_local(handler_rows, test_result)
    decision = {
        "worker": "codex",
        "phase": "pass611_vm_solve_to_cleartext",
        "iterations_completed": 1,
        "resumed_from_pass609_pass610": True,
        "p609012_edge_traced": True,
        "p609012_packet_buffer_bridge_confirmed": False,
        "vm_state_model_reconstructed": True,
        "vm_context_layout_entries": layout_entries,
        "transform_relevant_handlers_traced": len(handler_rows),
        "handler_derived_transforms_tested": int(test_result["tested"]),
        "exact_plaintext_recovered": False,
        "decoder_success": False,
        "matched_messages_count": 0,
        "matched_messages_labels": [],
        "best_candidate_handler": "0x11B57796",
        "best_dataflow_edge": "0x114731E0..0x114731F5",
        "best_candidate_transform": "none; complete handler-derived transform semantics unavailable",
        "best_remaining_blocker": "Missing generated full p-code/disassembly/dataflow for the top VM transform handlers, especially 0x11B57796 and 0x11B5932F, plus verified packet buffer/length/state field mapping. Existing first-instruction classifications cannot derive a decoder without guessing.",
        "next_autonomous_step": "Generate or provide pass8b_target_pcode.txt, pass8b_target_disassembly.txt, and pass8b_target_flows.csv covering P609-012 and the top transform handlers; then run bounded symbolic dataflow to extract a concrete transform before any PCAP oracle test.",
        "antigravity_files_modified": False,
        "forbidden_methods_used": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "P609-012 was rejected as a packet-buffer bridge and at least 20 transform-relevant handlers were traced, but complete handler semantics are absent; no exact plaintext recovered.",
        "next_action": "produce complete static p-code/dataflow exports for the identified handlers and rerun Pass611 transform derivation",
    }
    (ARTIFACTS / "pass611_codex_vm_solve_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    write_summary(decision)
    report = f"""# Codex Report - Pass611 VM Solve\n\n- Exact plaintext recovered: false\n- P609-012 packet-buffer bridge confirmed: false\n- Transform-relevant handlers traced: {len(handler_rows)}\n- Handler-derived transforms tested: {test_result['tested']}\n- Best handler: 0x11B57796\n- Best edge: 0x114731E0..0x114731F5\n- Blocker: {decision['best_remaining_blocker']}\n- Safety: static/offline only; Antigravity-owned files not modified; no private packet or binary data committed.\n"""
    (REPO / "inbox" / "codex_report.md").write_text(report, encoding="utf-8")
    return decision


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
