#!/usr/bin/env python3
from __future__ import annotations
import json, shutil, tempfile, unittest
from collections import Counter, defaultdict
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RIP, UC_X86_REG_RSP
from clean_checkpoint_v2 import CheckpointError, MANIFEST, load_checkpoint, save_checkpoint, validate_manifest

class Dummy:
    def __init__(self):
        self.uc=Uc(UC_ARCH_X86,UC_MODE_64); self.uc.mem_map(0x1000,0x2000,UC_PROT_READ|UC_PROT_WRITE)
        self.uc.mem_write(0x1000,b"pass676"+b"\0"*(0x2000-7)); self.uc.reg_write(UC_X86_REG_RAX,0x123456789abcdef0)
        self.uc.reg_write(UC_X86_REG_RSP,0x2ff0); self.uc.reg_write(UC_X86_REG_RIP,0x1010)
        self.insn=17; self.stop="checkpoint_boundary"; self.last_rip=0x1010
        self.api_by_addr={0x6000000000:("kernel32","VirtualAlloc")}; self.api_calls=[{"i":7,"name":"VirtualAlloc"}]
        self.next_api=0x6000000010; self.fake_modules={"kernel32.dll":0x6100000000}; self.fake_module_next=0x6101000000
        self.import_names=defaultdict(list,{"kernel32.dll":["VirtualAlloc"]}); self.next_heap=0x70000000; self.heap_end=0x71000000
        self.next_handle=0x1008; self.mapped_pages={0x1000,0x2000}; self.dynamic_maps=[]; self.image_writes=Counter({0x1000:1})
        self.image_write_ranges=[(0x1000,4,1,17)]; self.executed_pages=Counter({0x1000:17}); self.hot=Counter(); self.invalid_insn=[]
        self.first_zero_text_write=None; self.zero_regions=[]; self.stack_base=0x1000; self.stack_size=0x2000; self.stack_top=0x3000
        self.api_base=0x6000000000; self.api_size=0x1000; self.sentinel=0x1010; self.teb=0; self.peb=0; self.total_instructions=17
        self.mapping_protection_events=[{"api":"VirtualAlloc","mapping_changed":True}]
        obj={"path":"logical-game-input","pos":3,"data":b"abc123"}
        self.file_handles={0x1000:obj}; self.mapping_handles={0x1004:obj}

class CheckpointV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp(prefix="pass676_test_"))
        self.identity={"files":{"script":{"sha256":"a"*64},"input":{"sha256":"c"*64}},"deterministic_configuration":{"rflags":0x202}}
        self.hooks={"profile":"synthetic-v2","invalid_page_mapping":False}
    def tearDown(self): shutil.rmtree(self.tmp)
    def save(self,dummy=None,name="checkpoint"):
        cp=self.tmp/name; save_checkpoint(dummy or Dummy(),cp,self.identity,self.hooks); return cp
    def clone(self,cp,name):
        dst=self.tmp/name; shutil.copytree(cp,dst); return dst
    def restore(self,cp):
        restored=Dummy(); load_checkpoint(restored,cp,self.identity,self.hooks); return restored

    def test_open_file_and_mapping_alias_roundtrip(self):
        cp=self.save(); restored=self.restore(cp)
        self.assertIs(restored.mapping_handles[0x1004],restored.file_handles[0x1000])
        self.assertEqual(restored.mapping_handles[0x1004]["data"],b"abc123")

    def test_mapping_survives_closed_file_handle_roundtrip(self):
        dummy=Dummy(); backing=dummy.mapping_handles[0x1004]; dummy.file_handles.pop(0x1000)
        cp=self.save(dummy); restored=self.restore(cp)
        self.assertEqual(restored.file_handles,{})
        self.assertEqual(restored.mapping_handles[0x1004]["data"],b"abc123")
        self.assertEqual(restored.mapping_handles[0x1004]["path"],"logical-game-input")
        self.assertIsNotNone(backing)

    def test_two_mapping_handles_preserve_orphan_alias(self):
        dummy=Dummy(); obj=dummy.mapping_handles[0x1004]; dummy.file_handles.clear(); dummy.mapping_handles[0x1008]=obj
        restored=self.restore(self.save(dummy))
        self.assertIs(restored.mapping_handles[0x1004],restored.mapping_handles[0x1008])

    def test_distinct_equal_objects_remain_distinct(self):
        dummy=Dummy(); dummy.file_handles={}
        dummy.mapping_handles={0x1004:{"path":"x","pos":0,"data":b"same"},0x1008:{"path":"x","pos":0,"data":b"same"}}
        restored=self.restore(self.save(dummy))
        self.assertIsNot(restored.mapping_handles[0x1004],restored.mapping_handles[0x1008])
        self.assertEqual(restored.mapping_handles[0x1004],restored.mapping_handles[0x1008])

    def test_dangling_object_reference_rejected(self):
        cp=self.save(); p=cp/MANIFEST; doc=json.loads(p.read_text()); doc["python_state"]["mapping_handles"][0]["object_id"]="absent"; p.write_text(json.dumps(doc))
        with self.assertRaisesRegex(CheckpointError,"references absent object"): validate_manifest(cp)

    def test_corrupt_object_payload_rejected(self):
        cp=self.save(); p=cp/"synthetic_objects.bin"; data=bytearray(p.read_bytes()); data[0]^=0xff; p.write_bytes(data)
        with self.assertRaisesRegex(CheckpointError,"hash/size mismatch"): validate_manifest(cp)

    def test_duplicate_object_id_rejected(self):
        dummy=Dummy(); dummy.mapping_handles[0x1008]={"path":"other","pos":0,"data":b"other"}; cp=self.save(dummy)
        p=cp/MANIFEST; doc=json.loads(p.read_text()); doc["python_state"]["synthetic_objects"][1]["object_id"]=doc["python_state"]["synthetic_objects"][0]["object_id"]; p.write_text(json.dumps(doc))
        with self.assertRaisesRegex(CheckpointError,"duplicate or invalid synthetic object id"): validate_manifest(cp)

    def test_v1_schema_rejected_by_v2_loader(self):
        cp=self.save(); p=cp/MANIFEST; doc=json.loads(p.read_text()); doc["schema_version"]="aion-clean-checkpoint/v1"; p.write_text(json.dumps(doc))
        with self.assertRaisesRegex(CheckpointError,"unsupported schema"): validate_manifest(cp)

    def test_immutable_nonoverwrite(self):
        cp=self.save()
        with self.assertRaisesRegex(CheckpointError,"refusing to overwrite"): save_checkpoint(Dummy(),cp,self.identity,self.hooks)

if __name__=="__main__": unittest.main(verbosity=2)
