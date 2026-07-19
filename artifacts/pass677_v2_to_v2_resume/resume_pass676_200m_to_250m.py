#!/usr/bin/env python3
"""Pass677: load the immutable Pass676 200M v2 checkpoint, execute at most one
50M clean segment, preserve an event checkpoint on early stop, and otherwise
save/validate the exact 250M state with the unchanged v2 synthetic-object graph.

Historical Pass674-Pass676 artifacts are read-only.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ["AION_DECODER_ROOT"]).resolve()
PASS675 = ROOT / "outbox" / "pass675_checkpointed_receive_bridge_replay"
PASS676 = ROOT / "outbox" / "pass676_checkpoint_object_table_resume"
SOURCE = PASS676 / "checkpoint_0200000000_v2"
OUT = ROOT / "outbox" / "pass677_v2_to_v2_resume"
EXPECTED_SOURCE_MANIFEST_SHA256 = "3c95946844fe4ca09426feb309d9708b8b906183d0815d9d98f64cd7c0875270"
EXPECTED_V1_SOURCE_MANIFEST_SHA256 = "09d08715a4ab3b5c62bc7f756f8e65fd2744dc970562ef36d3d55163a45315c7"
SOURCE_INSTRUCTIONS = 200_000_000
SEGMENT = 50_000_000
TARGET_INSTRUCTIONS = SOURCE_INSTRUCTIONS + SEGMENT


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


def source_identity(v2, old) -> dict:
    """Reconstruct the exact identity embedded by the unmodified Pass676 driver."""
    return v2.hash_identity(
        {
            "pass676_resume_driver": PASS676 / "resume_pass675_150m_to_200m.py",
            "checkpoint_v2": PASS676 / "clean_checkpoint_v2.py",
            "source_pass675_driver": PASS675 / "run_pass675_checkpointed_replay.py",
            "source_checkpoint_v1": PASS675 / "checkpoint_0150000000" / "checkpoint_manifest.json",
            "pass673_watcher": old.PASS673 / "continue_receive_bridge_replay.py",
            "checkpoint_replay_wrapper": old.PASS674 / "checkpoint_clean_replay.py",
            "clean_replay_script": old.replay.V6,
            "base_replay_script": old.replay.V2,
            "patched_emulator": old.replay.LOADER,
            "game_input": old.replay.GAME,
        },
        {
            "source_instruction_count": 150_000_000,
            "continuation_instruction_count": 50_000_000,
            "target_instruction_count": 200_000_000,
            "source_manifest_sha256": EXPECTED_V1_SOURCE_MANIFEST_SHA256,
            "migration": "v1-loaded-with-unchanged-v1-code_then-v2-save",
        },
    )


def target_identity(v2, old, actual_count: int, stop_reason: str) -> dict:
    return v2.hash_identity(
        {
            "pass677_resume_driver": Path(__file__).resolve(),
            "checkpoint_v2": PASS676 / "clean_checkpoint_v2.py",
            "source_pass676_driver": PASS676 / "resume_pass675_150m_to_200m.py",
            "source_checkpoint_v2": SOURCE / v2.MANIFEST,
            "source_pass675_driver": PASS675 / "run_pass675_checkpointed_replay.py",
            "pass673_watcher": old.PASS673 / "continue_receive_bridge_replay.py",
            "checkpoint_replay_wrapper": old.PASS674 / "checkpoint_clean_replay.py",
            "clean_replay_script": old.replay.V6,
            "base_replay_script": old.replay.V2,
            "patched_emulator": old.replay.LOADER,
            "game_input": old.replay.GAME,
        },
        {
            "source_instruction_count": SOURCE_INSTRUCTIONS,
            "requested_continuation_instruction_count": SEGMENT,
            "actual_target_instruction_count": actual_count,
            "source_manifest_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
            "checkpoint_schema": v2.SCHEMA_VERSION,
            "segment_stop_reason": stop_reason,
            "continuation": "v2-loaded-with-unchanged-v2-code_then-v2-save",
        },
    )


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
                    f"resolved={consumer['resolved_target_va']:#x}; {consumer['calculation']}"
                )
    return changed, scan, disassembly


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    allowed = {
        Path(__file__).name,
        "README.md",
        "CODEX_PROMPT.txt",
        "SHA256SUMS.txt",
        "test_results.txt",
        "__pycache__",
    }
    unexpected = [item.name for item in OUT.iterdir() if item.name not in allowed]
    if unexpected:
        raise SystemExit(f"refusing output directory with unexpected artifacts: {unexpected}")

    source_manifest = SOURCE / "checkpoint_manifest.json"
    if sha256_file(source_manifest) != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise SystemExit("source 200M v2 manifest hash mismatch")
    if sha256_file(PASS675 / "checkpoint_0150000000" / "checkpoint_manifest.json") != EXPECTED_V1_SOURCE_MANIFEST_SHA256:
        raise SystemExit("historical 150M v1 manifest hash mismatch")

    old = load(PASS675 / "run_pass675_checkpointed_replay.py", "pass677_pass675")
    v2 = load(PASS676 / "clean_checkpoint_v2.py", "pass677_checkpoint_v2")
    hooks = old.hook_config()
    klass = old.build_watch_class()

    expected_source_identity = source_identity(v2, old)
    em = old.new_emulator(klass)
    source_manifest_doc = v2.load_checkpoint(em, SOURCE, expected_source_identity, hooks)
    if em.total_instructions != SOURCE_INSTRUCTIONS:
        raise SystemExit(f"unexpected source instruction count: {em.total_instructions}")

    before_pages = old.mapped_page_snapshot(em)
    source_validation = {
        "checkpoint_id": SOURCE.name,
        "manifest_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
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
    (OUT / "source_checkpoint_validation.json").write_text(
        json.dumps(source_validation, indent=2), encoding="utf8"
    )

    reason = old.replay.run_segment(em, SEGMENT)
    actual_count = em.total_instructions
    exact_boundary = reason == "segment_instruction_limit" and actual_count == TARGET_INSTRUCTIONS
    target_identity_value = target_identity(v2, old, actual_count, reason)

    if exact_boundary:
        checkpoint_dir = OUT / "checkpoint_0250000000_v2"
    else:
        checkpoint_dir = OUT / (
            f"checkpoint_event_after_{SOURCE_INSTRUCTIONS:010d}_"
            f"{em.uc.reg_read(old.UC_X86_REG_RIP):016x}_v2"
        )

    em.stop = "checkpoint_boundary" if exact_boundary else reason
    v2.save_checkpoint(em, checkpoint_dir, target_identity_value, hooks)
    em.stop = ""
    target_manifest, _ = v2.validate_manifest(
        checkpoint_dir, target_identity_value, hooks
    )

    loaded = old.new_emulator(klass)
    v2.load_checkpoint(loaded, checkpoint_dir, target_identity_value, hooks)
    before_reload = v2.state_digest(em, reason)
    after_reload = v2.state_digest(loaded, reason)
    equivalent = v2.canonical_json(before_reload) == v2.canonical_json(after_reload)

    comparison = {
        "exact_equivalence": equivalent,
        "source_manifest_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
        "target_manifest_sha256": sha256_file(checkpoint_dir / v2.MANIFEST),
        "requested_target_instruction_count": TARGET_INSTRUCTIONS,
        "actual_instruction_count": loaded.total_instructions,
        "segment_stop_reason": reason,
        "exact_250m_boundary": exact_boundary,
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
    (OUT / "state_comparison.json").write_text(
        json.dumps(comparison, indent=2), encoding="utf8"
    )
    if not equivalent:
        raise SystemExit("v2-to-v2 save/load state mismatch")

    after_pages = old.mapped_page_snapshot(loaded)
    changed, scan, disassembly = scan_delta(old, before_pages, after_pages, loaded)
    write_csv(
        OUT / "changed_page_manifest.csv",
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
    write_csv(OUT / "receive_pointer_delta_scan.csv", scan, scan_fields)
    (OUT / "candidate_disassembly.txt").write_text(
        "\n".join(disassembly) + ("\n" if disassembly else ""),
        encoding="utf8",
    )

    image = old.image_bytes(loaded)
    provider_nonzero = any(old.page_bytes(image, old.PROVIDER_PAGE))
    decision = {
        "decision": (
            "v2_to_v2_250m_checkpoint_validated"
            if exact_boundary
            else "relevant_or_deterministic_event_preserved_before_250m"
        ),
        "source_checkpoint": SOURCE.name,
        "target_checkpoint": checkpoint_dir.name,
        "source_instruction_count": SOURCE_INSTRUCTIONS,
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
    (OUT / "pass677_decision.json").write_text(
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
    (OUT / "checkpoint_validation.json").write_text(
        json.dumps(validation, indent=2), encoding="utf8"
    )

    print(
        json.dumps(
            {
                "segment_stop_reason": reason,
                "instruction_count": loaded.total_instructions,
                "rip": comparison["rip"],
                "checkpoint": checkpoint_dir.name,
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
