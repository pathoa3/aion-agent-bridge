"""Pass611 handler-derived transform gate.

This file deliberately refuses to turn first-instruction labels into random crypto
trials. A transform is testable here only when complete handler semantics are
available from file-backed p-code/disassembly/dataflow.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from parse_existing_vm_exports import LOCAL_OUT


def append_local_failure(reason: str) -> None:
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    with (LOCAL_OUT / "failed_attempts_full.csv").open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(["timestamp", "candidate", "reason", "next_step"])
        writer.writerow([datetime.now(timezone.utc).isoformat(), "handler_derived_transform", reason, "provide full handler p-code/dataflow"])


def run_tests(handler_rows: list[dict[str, str]]) -> dict[str, object]:
    complete_semantics = [r for r in handler_rows if r.get("bounded_transform_possible") == "yes_complete"]
    if not complete_semantics:
        append_local_failure("no complete handler semantics available; first-instruction classifications cannot define a decoder")
        return {
            "tested": 0,
            "decoder_success": False,
            "exact_plaintext_recovered": False,
            "matched_messages": [],
            "reason": "No handler-derived transform was tested because available artifacts lack complete p-code/dataflow semantics.",
        }
    return {
        "tested": 0,
        "decoder_success": False,
        "exact_plaintext_recovered": False,
        "matched_messages": [],
        "reason": "Complete semantics path not reached in this checkpoint.",
    }


if __name__ == "__main__":
    print(run_tests([]))
