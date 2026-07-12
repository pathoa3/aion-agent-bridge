#!/usr/bin/env python3
"""Postprocess local-only Pass622 Ghidra exports into Git-safe summaries."""

import argparse
import csv
import json
from pathlib import Path

NETWORK_APIS = {"recv", "WSARecv", "recvfrom", "ReadFile", "InternetReadFile"}
SEND_APIS = {"send", "WSASend", "connect", "select", "ioctlsocket", "closesocket"}
VM_ANCHORS = {"0x11B562BD", "0x11B5630F", "0x11B5932F", "0x11B57796", "0x11B55DF6", "0x11B54E6F", "0x11B566B4", "0x11B56C63"}


def read_json(path):
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f))


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def classify_targets(export_dir):
    funcs = read_json(export_dir / "candidate_functions.json") or read_csv(export_dir / "candidate_functions.csv")
    imports = read_json(export_dir / "import_refs.json") or read_csv(export_dir / "import_refs.csv")
    writes = read_json(export_dir / "write_hints.json") or read_csv(export_dir / "write_hints.csv")

    recv_by_entry = set()
    send_by_entry = set()
    for row in imports:
        api = row.get("api", "")
        entry = row.get("function_entry", "")
        if api in NETWORK_APIS and entry:
            recv_by_entry.add(entry)
        if api in SEND_APIS and entry:
            send_by_entry.add(entry)

    write_by_entry = {}
    for row in writes:
        entry = row.get("function_entry", "")
        if not entry:
            continue
        write_by_entry.setdefault(entry, []).append(row)

    targets = []
    keyslots = []
    for idx, row in enumerate(funcs, 1):
        entry = row.get("entry", "")
        name = row.get("name", "")
        anchor_hits = row.get("vm_anchor_hits", "")
        recv_related = entry in recv_by_entry or row.get("caller_depth", "") != ""
        vm_related = bool(anchor_hits)
        writes_here = write_by_entry.get(entry, [])
        key_related = any("8-byte" in w.get("pattern", "") or "key-arithmetic" in w.get("pattern", "") for w in writes_here)
        score = (3 if entry in recv_by_entry else 0) + (2 if vm_related else 0) + (2 if key_related else 0)
        confidence = "high" if score >= 5 else "medium" if score >= 3 else "low"
        reason_bits = []
        if entry in recv_by_entry:
            reason_bits.append("direct receive/import caller")
        if entry in send_by_entry:
            reason_bits.append("send/control import caller")
        if vm_related:
            reason_bits.append("contains VM anchor " + anchor_hits)
        if key_related:
            reason_bits.append("contains 8-byte/key-arithmetic write hint")
        if not reason_bits:
            reason_bits.append("within caller/callee walk")
        targets.append({
            "target_id": "P622-GH-%03d" % idx,
            "function_or_address": "%s %s" % (entry, name),
            "source_reason": "; ".join(reason_bits),
            "recv_related": str(bool(recv_related)).lower(),
            "vm_related": str(bool(vm_related)).lower(),
            "keyslot_write_related": str(bool(key_related)).lower(),
            "confidence": confidence,
            "next_export_or_trace": "trace decompile/dataflow from recv buffer into VM context and verify adjacent send/recv key slot writes" if confidence != "low" else "keep as graph context only"
        })
        for widx, w in enumerate(writes_here, 1):
            pattern = w.get("pattern", "")
            if "8-byte" in pattern or "key-arithmetic" in pattern:
                keyslots.append({
                    "candidate_id": "P622-KS-%03d" % (len(keyslots) + 1),
                    "function_or_address": "%s %s" % (entry, name),
                    "write_pattern": pattern,
                    "evidence": "Git-safe write hint: " + w.get("line", "")[:160],
                    "possible_role": "possible S2C rolling-key slot write if reachable from receive/world handshake path",
                    "confidence": "medium" if recv_related or vm_related else "low",
                    "next_test": "inspect local p-code/decompile for source seed, context base, and direction slot offset; do not commit raw export bytes"
                })
    targets.sort(key=lambda r: {"high": 0, "medium": 1, "low": 2}.get(r["confidence"], 3))
    return targets, keyslots


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default=r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports")
    ap.add_argument("--repo-root", default=r"C:\AionTools\aion-agent-bridge")
    ns = ap.parse_args()
    export_dir = Path(ns.export_dir)
    repo = Path(ns.repo_root)
    artifacts = repo / "artifacts"

    targets, keyslots = classify_targets(export_dir)
    write_csv(artifacts / "pass622_codex_s2c_receive_export_targets.csv",
              ["target_id", "function_or_address", "source_reason", "recv_related", "vm_related", "keyslot_write_related", "confidence", "next_export_or_trace"], targets)
    write_csv(artifacts / "pass622_codex_s2c_keyslot_write_candidates.csv",
              ["candidate_id", "function_or_address", "write_pattern", "evidence", "possible_role", "confidence", "next_test"], keyslots)

    decision = {
        "worker": "codex",
        "phase": "pass622_ghidra_s2c_receive_export_generator_postprocess",
        "ghidra_exports_generated_locally": export_dir.exists() and bool(list(export_dir.glob("*"))),
        "receive_export_targets_count": len(targets),
        "keyslot_write_candidates_count": len(keyslots),
        "s2c_initial_key_found": False,
        "s2c_key_write_path_found": False,
        "recv_handshake_path_found": any(t["recv_related"] == "true" and t["vm_related"] == "true" for t in targets),
        "bounded_s2c_validation_run": False,
        "s2c_decoder_success": False,
        "private_payload_committed": False,
        "raw_binary_committed": False,
        "reason": "Postprocessed local Ghidra exports into Git-safe target and keyslot tables; a concrete key still requires manual/local review of exported p-code/decompile slices.",
        "next_action": "If targets exist, inspect local-only p-code/decompile for receive-buffer-to-VM-context path and S2C key-slot offset."
    }
    (artifacts / "pass622_codex_s2c_export_postprocess_decision.json").write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
