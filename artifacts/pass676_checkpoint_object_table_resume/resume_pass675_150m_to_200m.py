#!/usr/bin/env python3
"""Pass676: load the immutable Pass675 150M v1 checkpoint, run exactly one
50M clean segment, and save/validate the resulting 200M state with the v2
synthetic-object graph.  Historical Pass675 artifacts are read-only.
"""
from __future__ import annotations
import csv, hashlib, importlib.util, json, os, sys
from pathlib import Path

ROOT=Path(os.environ["AION_DECODER_ROOT"]).resolve()
PASS675=ROOT/"outbox"/"pass675_checkpointed_receive_bridge_replay"
SOURCE=PASS675/"checkpoint_0150000000"
OUT=ROOT/"outbox"/"pass676_checkpoint_object_table_resume"
EXPECTED_SOURCE_MANIFEST_SHA256="09d08715a4ab3b5c62bc7f756f8e65fd2744dc970562ef36d3d55163a45315c7"
SEGMENT=50_000_000


def load(path:Path,name:str):
    spec=importlib.util.spec_from_file_location(name,str(path)); mod=importlib.util.module_from_spec(spec)
    sys.modules[name]=mod; spec.loader.exec_module(mod); return mod


def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1<<20),b""): h.update(block)
    return h.hexdigest()


def write_csv(path:Path,rows:list[dict],fields:list[str]):
    with path.open("w",newline="",encoding="utf8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for row in rows: w.writerow({k:row.get(k,"") for k in fields})


def main()->int:
    OUT.mkdir(parents=True,exist_ok=True)
    allowed={
        "clean_checkpoint_v2.py", "checkpoint_schema_v2.json",
        "test_clean_checkpoint_v2.py", "resume_pass675_150m_to_200m.py",
        "README.md", "CODEX_PROMPT.txt", "SHA256SUMS.txt", "__pycache__",
        "test_results.txt",
    }
    unexpected=[item.name for item in OUT.iterdir() if item.name not in allowed]
    if unexpected:
        raise SystemExit(f"refusing output directory with unexpected artifacts: {unexpected}")
    source_manifest=SOURCE/"checkpoint_manifest.json"
    if sha256_file(source_manifest)!=EXPECTED_SOURCE_MANIFEST_SHA256:
        raise SystemExit("source 150M manifest hash mismatch")

    # Import the unchanged historical Pass675 driver and v1 serializer so its
    # embedded identity remains verifiable.  Do not patch either historical file.
    old=load(PASS675/"run_pass675_checkpointed_replay.py","pass676_old_pass675")
    v1=old.checkpoint
    v2=load(Path(__file__).with_name("clean_checkpoint_v2.py"),"pass676_checkpoint_v2")
    old_identity=old.identity(); hooks=old.hook_config(); Klass=old.build_watch_class()
    em=old.new_emulator(Klass)
    v1.load_checkpoint(em,SOURCE,old_identity,hooks)
    if em.total_instructions!=150_000_000: raise SystemExit(f"unexpected source instruction count: {em.total_instructions}")

    before_pages=old.mapped_page_snapshot(em)
    before_slots=old.slot_values(em)
    reason=old.replay.run_segment(em,SEGMENT)
    if reason!="segment_instruction_limit" or em.total_instructions!=200_000_000:
        state=v2.state_digest(em,reason)
        (OUT/"early_stop_state.json").write_text(json.dumps(state,indent=2),encoding="utf8")
        raise SystemExit(f"segment ended early: {reason}")

    v2_identity=v2.hash_identity({
        "pass676_resume_driver":Path(__file__).resolve(),
        "checkpoint_v2":Path(v2.__file__).resolve(),
        "source_pass675_driver":PASS675/"run_pass675_checkpointed_replay.py",
        "source_checkpoint_v1":source_manifest,
        "pass673_watcher":old.PASS673/"continue_receive_bridge_replay.py",
        "checkpoint_replay_wrapper":old.PASS674/"checkpoint_clean_replay.py",
        "clean_replay_script":old.replay.V6,
        "base_replay_script":old.replay.V2,
        "patched_emulator":old.replay.LOADER,
        "game_input":old.replay.GAME,
    },{
        "source_instruction_count":150_000_000,
        "continuation_instruction_count":SEGMENT,
        "target_instruction_count":200_000_000,
        "source_manifest_sha256":EXPECTED_SOURCE_MANIFEST_SHA256,
        "migration":"v1-loaded-with-unchanged-v1-code_then-v2-save",
    })

    cp=OUT/"checkpoint_0200000000_v2"
    em.stop="checkpoint_boundary"; v2.save_checkpoint(em,cp,v2_identity,hooks); em.stop=""
    manifest,_=v2.validate_manifest(cp,v2_identity,hooks)
    loaded=old.new_emulator(Klass); v2.load_checkpoint(loaded,cp,v2_identity,hooks)
    a=v2.state_digest(em,"segment_instruction_limit")
    b=v2.state_digest(loaded,"segment_instruction_limit")
    equivalent=v2.canonical_json(a)==v2.canonical_json(b)
    comparison={
        "exact_equivalence":equivalent,
        "source_manifest_sha256":EXPECTED_SOURCE_MANIFEST_SHA256,
        "target_manifest_sha256":sha256_file(cp/v2.MANIFEST),
        "instruction_count":loaded.total_instructions,
        "rip":hex(loaded.uc.reg_read(old.UC_X86_REG_RIP)),
        "api_count":len(loaded.api_calls),
        "file_handle_count":len(loaded.file_handles),
        "mapping_handle_count":len(loaded.mapping_handles),
        "orphan_mapping_handles":[hex(h) for h,obj in sorted(loaded.mapping_handles.items()) if all(obj is not x for x in loaded.file_handles.values())],
    }
    (OUT/"state_comparison.json").write_text(json.dumps(comparison,indent=2),encoding="utf8")
    if not equivalent: raise SystemExit("v2 save/load state mismatch")

    after_pages=old.mapped_page_snapshot(loaded); after_slots=old.slot_values(loaded)
    changed=[]; scan=[]; dis=[]
    exec_pages=old.executable_pages(loaded)
    for va in sorted(set(before_pages)|set(after_pages)):
        before,bp=before_pages.get(va,(bytes(old.PAGE),"")); after,ap=after_pages.get(va,(bytes(old.PAGE),""))
        if before==after: continue
        is_exec=va in exec_pages
        changed.append({"page_va":hex(va),"executable":is_exec,"before_sha256":old.sha256_bytes(before),"after_sha256":old.sha256_bytes(after),"before_permissions":bp,"permissions":ap})
        for row in old.watch.scan_pointer_copies(va,after,after_slots):
            row["classification"]="non_iat_receive_pointer_copy"; scan.append(row)
        if is_exec:
            for row in old.watch.scan_exact_slot_readers(after,va):
                row["classification"]="exact_receive_slot_reader"; scan.append(row)
                dis.append(f"{row['instruction_va']:#x}: {row['bytes']} {row['mnemonic']} {row['op_str']} resolved={row['resolved_slot_va']:#x}")
    occurrences={r["occurrence_va"] for r in scan if "occurrence_va" in r}
    if occurrences:
        changed_exec={int(row["page_va"],16) for row in changed if row["executable"]}
        for va in sorted(changed_exec):
            for row in old.scan_consumers(after_pages[va][0],va,occurrences): scan.append(row)
    write_csv(OUT/"changed_page_manifest.csv",changed,["page_va","executable","before_sha256","after_sha256","before_permissions","permissions"])
    fields=sorted({k for row in scan for k in row}) if scan else ["classification"]
    write_csv(OUT/"receive_pointer_delta_scan.csv",scan,fields)
    (OUT/"candidate_disassembly.txt").write_text("\n".join(dis)+("\n" if dis else ""),encoding="utf8")

    provider=old.page_bytes(old.image_bytes(loaded),old.PROVIDER_PAGE)
    decision={
        "decision":"v2_checkpoint_object_graph_validated" if equivalent else "not_validated",
        "source_checkpoint":"checkpoint_0150000000",
        "target_checkpoint":cp.name,
        "instruction_count":loaded.total_instructions,
        "provider_page_nonzero":any(provider),
        "receive_candidates":len(scan),
        "changed_pages":len(changed),
        "synthetic_object_result":comparison,
        "proven_fact":"The v1 failure was a serializer-model mismatch: a mapping-owned object survived CloseHandle after its file-handle table entry was removed.",
        "claim_limit":"No receive bridge is claimed without exact executable reader/callsite and buffer-handoff evidence.",
    }
    (OUT/"pass676_decision.json").write_text(json.dumps(decision,indent=2),encoding="utf8")
    return 0

if __name__=="__main__": raise SystemExit(main())
