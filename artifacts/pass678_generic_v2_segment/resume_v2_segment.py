#!/usr/bin/env python3
"""Generic bounded continuation for an immutable EuroAion clean v2 checkpoint.

The source checkpoint identity is accepted only after the caller supplies and the
script verifies the exact SHA-256 of checkpoint_manifest.json. The manifest's
embedded identity is then used as the expected identity for the unchanged v2
loader. One segment is executed, an event or exact-boundary checkpoint is saved,
reloaded, compared byte-for-byte through state_digest, and only changed pages are
scanned with the established Pass675 watcher logic.

No live process, forced control flow, state seeding, synthetic return, invalid-page
mapping, binary patching, hook injection, or production-file modification occurs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


def validate_args(expected_hash: str, source_count: int, segment_count: int) -> str:
    normalized = expected_hash.strip().lower()
    if not HEX64.fullmatch(normalized):
        raise ValueError("expected source manifest SHA-256 must be 64 lowercase hex characters")
    if source_count < 0:
        raise ValueError("source instruction count must be non-negative")
    if segment_count <= 0:
        raise ValueError("segment instruction count must be positive")
    return normalized


def verified_source_identity(source: Path, expected_hash: str) -> tuple[dict, dict]:
    manifest_path = source / "checkpoint_manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError(f"missing source manifest: {manifest_path}")
    actual = sha256_file(manifest_path)
    if actual != expected_hash:
        raise RuntimeError(
            f"source manifest hash mismatch: expected {expected_hash}, actual {actual}"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    except Exception as exc:
        raise RuntimeError(f"source manifest JSON parse failure: {exc}") from exc
    identity = manifest.get("identity")
    if not isinstance(identity, dict) or not identity:
        raise RuntimeError("source manifest lacks a non-empty identity object")
    if manifest.get("schema_version") != "aion-clean-checkpoint/v2":
        raise RuntimeError(
            f"source checkpoint is not v2: {manifest.get('schema_version')!r}"
        )
    return manifest, identity


def scan_delta(old, before_pages, after_pages, loaded):
    after_slots = old.slot_values(loaded)
    exec_pages = old.executable_pages(loaded)
    changed: list[dict] = []
    scan: list[dict] = []
    disassembly: list[str] = []

    for va in sorted(set(before_pages) | set(after_pages)):
        before, before_permissions = before_pages.get(va, (bytes(old.PAGE), ""))
        after, after_permissions = after_pages.get(va, (bytes(old.PAGE), ""))
        if before == after:
            continue
        is_exec = va in exec_pages
        reasons = []
        if va == old.PROVIDER_PAGE and not any(before) and any(after):
            reasons.append("provider_zero_to_nonzero")
        if va == old.IAT_PAGE:
            reasons.append("receive_iat_page_changed")
        if is_exec:
            reasons.append("executable_page_changed")
        changed.append(
            {
                "page_va": hex(va),
                "executable": is_exec,
                "before_sha256": old.sha256_bytes(before),
                "after_sha256": old.sha256_bytes(after),
                "before_nonzero": any(before),
                "after_nonzero": any(after),
                "change_reason": ";".join(reasons),
                "before_permissions": before_permissions,
                "permissions": after_permissions,
            }
        )
        for row in old.watch.scan_pointer_copies(va, after, after_slots):
            row["classification"] = "non_iat_receive_pointer_copy"
            scan.append(row)
        if is_exec:
            for row in old.watch.scan_exact_slot_readers(after, va):
                row["classification"] = "exact_receive_slot_reader"
                scan.append(row)
                disassembly.append(
                    f"{row['instruction_va']:#x}: {row['bytes']} "
                    f"{row['mnemonic']} {row['op_str']} "
                    f"resolved={row['resolved_slot_va']:#x}; {row['calculation']}"
                )

    occurrences = {row["occurrence_va"] for row in scan if "occurrence_va" in row}
    if occurrences:
        for row in changed:
            if not row["executable"]:
                continue
            va = int(row["page_va"], 16)
            for consumer in old.scan_consumers(after_pages[va][0], va, occurrences):
                scan.append(consumer)
                disassembly.append(
                    f"{consumer['instruction_va']:#x}: {consumer['bytes']} "
                    f"{consumer['mnemonic']} {consumer['op_str']} "
                    f"resolved={consumer['resolved_target_va']:#x}; "
                    f"{consumer['calculation']}"
                )
    return changed, scan, disassembly


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-checkpoint", type=Path, required=True)
    parser.add_argument("--expected-source-manifest-sha256", required=True)
    parser.add_argument("--source-instructions", type=int, required=True)
    parser.add_argument("--segment-instructions", type=int, default=50_000_000)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pass-id", default="pass678")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    expected_hash = validate_args(
        args.expected_source_manifest_sha256,
        args.source_instructions,
        args.segment_instructions,
    )
    root_value = os.environ.get("AION_DECODER_ROOT")
    if not root_value:
        raise SystemExit("AION_DECODER_ROOT is required")
    root = Path(root_value).resolve()
    source = args.source_checkpoint.resolve()
    out = args.out.resolve()
    pass675 = root / "outbox" / "pass675_checkpointed_receive_bridge_replay"
    pass676 = root / "outbox" / "pass676_checkpoint_object_table_resume"

    out.mkdir(parents=True, exist_ok=True)
    allowed = {
        Path(__file__).name,
        "README.md",
        "CODEX_PROMPT.txt",
        "SHA256SUMS.txt",
        "test_results.txt",
        "test_resume_v2_segment.py",
        "__pycache__",
    }
    unexpected = [item.name for item in out.iterdir() if item.name not in allowed]
    if unexpected:
        raise SystemExit(f"refusing output directory with unexpected artifacts: {unexpected}")

    source_manifest_doc, source_identity = verified_source_identity(source, expected_hash)
    old = load_module(pass675 / "run_pass675_checkpointed_replay.py", f"{args.pass_id}_pass675")
    v2 = load_module(pass676 / "clean_checkpoint_v2.py", f"{args.pass_id}_checkpoint_v2")
    hooks = old.hook_config()
    klass = old.build_watch_class()

    em = old.new_emulator(klass)
    loaded_source_manifest = v2.load_checkpoint(em, source, source_identity, hooks)
    if loaded_source_manifest != source_manifest_doc:
        raise SystemExit("source manifest changed between preflight and load")
    if em.total_instructions != args.source_instructions:
        raise SystemExit(
            f"unexpected source instruction count: {em.total_instructions}; "
            f"expected {args.source_instructions}"
        )

    before_pages = old.mapped_page_snapshot(em)
    source_validation = {
        "checkpoint_id": source.name,
        "manifest_sha256": expected_hash,
        "schema": source_manifest_doc["schema_version"],
        "loader_accepted": True,
        "instruction_count": em.total_instructions,
        "rip": hex(em.uc.reg_read(old.UC_X86_REG_RIP)),
        "api_count": len(em.api_calls),
        "file_handle_count": len(em.file_handles),
        "mapping_handle_count": len(em.mapping_handles),
        "orphan_mapping_handles": [
            hex(handle)
            for handle, obj in sorted(em.mapping_handles.items())
            if all(obj is not file_obj for file_obj in em.file_handles.values())
        ],
    }
    (out / "source_checkpoint_validation.json").write_text(
        json.dumps(source_validation, indent=2), encoding="utf8"
    )

    reason = old.replay.run_segment(em, args.segment_instructions)
    actual_count = em.total_instructions
    requested_target = args.source_instructions + args.segment_instructions
    exact_boundary = reason == "segment_instruction_limit" and actual_count == requested_target

    target_identity = v2.hash_identity(
        {
            f"{args.pass_id}_resume_driver": Path(__file__).resolve(),
            "checkpoint_v2": pass676 / "clean_checkpoint_v2.py",
            "source_checkpoint_v2": source / v2.MANIFEST,
            "source_pass675_driver": pass675 / "run_pass675_checkpointed_replay.py",
            "pass673_watcher": old.PASS673 / "continue_receive_bridge_replay.py",
            "checkpoint_replay_wrapper": old.PASS674 / "checkpoint_clean_replay.py",
            "clean_replay_script": old.replay.V6,
            "base_replay_script": old.replay.V2,
            "patched_emulator": old.replay.LOADER,
            "game_input": old.replay.GAME,
        },
        {
            "source_instruction_count": args.source_instructions,
            "requested_continuation_instruction_count": args.segment_instructions,
            "actual_target_instruction_count": actual_count,
            "source_manifest_sha256": expected_hash,
            "checkpoint_schema": v2.SCHEMA_VERSION,
            "segment_stop_reason": reason,
            "continuation": "verified-v2-manifest-identity_then-v2-save",
        },
    )

    if exact_boundary:
        checkpoint_dir = out / f"checkpoint_{requested_target:010d}_v2"
    else:
        checkpoint_dir = out / (
            f"checkpoint_event_after_{args.source_instructions:010d}_"
            f"{em.uc.reg_read(old.UC_X86_REG_RIP):016x}_v2"
        )

    em.stop = "checkpoint_boundary" if exact_boundary else reason
    v2.save_checkpoint(em, checkpoint_dir, target_identity, hooks)
    em.stop = ""
    target_manifest, _ = v2.validate_manifest(checkpoint_dir, target_identity, hooks)

    loaded = old.new_emulator(klass)
    v2.load_checkpoint(loaded, checkpoint_dir, target_identity, hooks)
    before_reload = v2.state_digest(em, reason)
    after_reload = v2.state_digest(loaded, reason)
    equivalent = v2.canonical_json(before_reload) == v2.canonical_json(after_reload)

    comparison = {
        "exact_equivalence": equivalent,
        "source_manifest_sha256": expected_hash,
        "target_manifest_sha256": sha256_file(checkpoint_dir / v2.MANIFEST),
        "requested_target_instruction_count": requested_target,
        "actual_instruction_count": loaded.total_instructions,
        "segment_stop_reason": reason,
        "exact_requested_boundary": exact_boundary,
        "rip": hex(loaded.uc.reg_read(old.UC_X86_REG_RIP)),
        "api_count": len(loaded.api_calls),
        "mapped_region_count": len(list(loaded.uc.mem_regions())),
        "file_handle_count": len(loaded.file_handles),
        "mapping_handle_count": len(loaded.mapping_handles),
        "orphan_mapping_handles": [
            hex(handle)
            for handle, obj in sorted(loaded.mapping_handles.items())
            if all(obj is not file_obj for file_obj in loaded.file_handles.values())
        ],
    }
    (out / "state_comparison.json").write_text(
        json.dumps(comparison, indent=2), encoding="utf8"
    )
    if not equivalent:
        raise SystemExit("v2-to-v2 save/load state mismatch")

    after_pages = old.mapped_page_snapshot(loaded)
    changed, scan, disassembly = scan_delta(old, before_pages, after_pages, loaded)
    write_csv(
        out / "changed_page_manifest.csv",
        changed,
        [
            "page_va",
            "executable",
            "before_sha256",
            "after_sha256",
            "before_nonzero",
            "after_nonzero",
            "change_reason",
            "before_permissions",
            "permissions",
        ],
    )
    scan_fields = sorted({key for row in scan for key in row}) if scan else ["classification"]
    write_csv(out / "receive_pointer_delta_scan.csv", scan, scan_fields)
    (out / "candidate_disassembly.txt").write_text(
        "\n".join(disassembly) + ("\n" if disassembly else ""), encoding="utf8"
    )

    image = old.image_bytes(loaded)
    provider_nonzero = any(old.page_bytes(image, old.PROVIDER_PAGE))
    decision = {
        "decision": (
            "requested_v2_boundary_checkpoint_validated"
            if exact_boundary
            else "relevant_or_deterministic_event_preserved_before_requested_boundary"
        ),
        "source_checkpoint": source.name,
        "target_checkpoint": checkpoint_dir.name,
        "source_instruction_count": args.source_instructions,
        "requested_target_instruction_count": requested_target,
        "actual_instruction_count": loaded.total_instructions,
        "segment_stop_reason": reason,
        "exact_state_equivalence": equivalent,
        "provider_page_nonzero": provider_nonzero,
        "receive_candidates": len(scan),
        "changed_pages": len(changed),
        "source_object_invariant": source_validation,
        "target_object_invariant": comparison,
        "claim_limit": (
            "No receive bridge is claimed without an exact executable reader/callsite "
            "and buffer-handoff evidence."
        ),
    }
    (out / f"{args.pass_id}_decision.json").write_text(
        json.dumps(decision, indent=2), encoding="utf8"
    )

    validation = {
        "source": source_validation,
        "target": {
            "checkpoint_id": checkpoint_dir.name,
            "schema": target_manifest["schema_version"],
            "manifest_sha256": comparison["target_manifest_sha256"],
            "loader_accepted": True,
            "exact_state_equivalence": equivalent,
            "instruction_count": loaded.total_instructions,
            "rip": comparison["rip"],
            "api_count": comparison["api_count"],
            "mapped_region_count": comparison["mapped_region_count"],
            "file_handle_count": comparison["file_handle_count"],
            "mapping_handle_count": comparison["mapping_handle_count"],
            "orphan_mapping_handles": comparison["orphan_mapping_handles"],
        },
        "delta": {
            "changed_pages": len(changed),
            "receive_candidates": len(scan),
            "provider_page_nonzero": provider_nonzero,
        },
    }
    (out / "checkpoint_validation.json").write_text(
        json.dumps(validation, indent=2), encoding="utf8"
    )

    print(
        json.dumps(
            {
                "segment_stop_reason": reason,
                "instruction_count": loaded.total_instructions,
                "rip": comparison["rip"],
                "checkpoint": checkpoint_dir.name,
                "target_manifest_sha256": comparison["target_manifest_sha256"],
                "exact_equivalence": equivalent,
                "changed_pages": len(changed),
                "receive_candidates": len(scan),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
