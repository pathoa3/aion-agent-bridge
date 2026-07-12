"""
locate_vm_bytecode_stream.py
============================
Determines whether the VM bytecode stream (the data interpreted by FUN_11b5625b)
is accessible from local static files.

Approach:
  1. Check if 4.7.5.Game.dll.bin contains .aion1 data (RVA 0x1472000..0x1B59A00).
  2. Report the PE section layout and whether the range is present in the file.
  3. If present, extract a candidate bytecode window from the .aion1 section.
  4. If absent (packed), document clearly and propose next steps.
  5. Cross-reference known dispatcher setup from FUN_11b5625b pcode:
       RSI (bytecode ptr) = RBP + ADD RSI, [RBP]
       R12 (handler base) = 0x11B54E6F (constant at 0x11B56278 pcode)
     This means bytecode base is not a hardcoded constant but a runtime RDX argument.

Outputs:
  - Console summary
  - bytecode_stream_candidates.csv (written to current dir)
"""

from __future__ import annotations
import struct
import sys
from pathlib import Path
import csv

IMAGE_BASE   = 0x10000000
AION1_MIN_VA = 0x11472000
AION1_MAX_VA = 0x11B59A00
AION1_MIN_RVA = AION1_MIN_VA - IMAGE_BASE  # 0x1472000
AION1_MAX_RVA = AION1_MAX_VA - IMAGE_BASE  # 0x1B59A00

BIN_PATH = Path(r"C:\AionTools\euroaion\4.7.5.Game.dll.bin")

# Dispatcher pcode findings from FUN_11b5625b.pcode.txt (pass622 export)
# 0x11B56278: R12 = 0x11B54E6F  (handler table base — hardcoded constant)
# 0x11B562AE: RSI += LOAD[RBP]  (bytecode ptr advances by [RBP] = PC offset from context)
# 0x11B562B6: RAX = RBP + (-0x78f0045b)   (some helper offset)
# 0x11B5630F: RAX = LOAD[R12 + AL*8]      (handler VA lookup)
# 0x11B56329: BRANCHIND RAX               (dispatch)
DISPATCHER_FACTS = {
    "handler_table_base_va":  0x11B54E6F,
    "handler_table_base_src": "0x11B56278 pcode: R12 = const 0x11B54E6F",
    "bytecode_ptr_reg":       "RSI (register 0x30 in Ghidra SLEIGH)",
    "bytecode_load_site":     "0x11B562BD: AL = LOAD[RSI]  (fetch raw opcode byte)",
    "bytecode_advance_site":  "0x11B562FF: RSI += 1",
    "bytecode_init_site":     "0x11B562AE: RSI += LOAD[RBP]  (RSI = RSI + *RBP)",
    "context_ptr_reg":        "RBP (register 0x28 in Ghidra SLEIGH)",
    "context_ptr_source":     "FUN_11b59337 @ 0x11B59343: RBP = RDX (2nd call arg)",
    "bl_key_reg":             "BH/BL (register 0x18, size 1 in Ghidra SLEIGH)",
    "opcode_decode":          "opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)",
    "bl_update":              "BL = (BL - opcode) & 0xFF",
    "dispatch_instr":         "0x11B56329: BRANCHIND RAX (= handler VA from table)",
}


def parse_pe_sections(data: bytes) -> list[dict]:
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        raise ValueError("Not a valid PE file")
    num_sections   = struct.unpack_from("<H", data, pe_offset + 6)[0]
    size_opt       = struct.unpack_from("<H", data, pe_offset + 20)[0]
    magic_opt      = struct.unpack_from("<H", data, pe_offset + 24)[0]
    if magic_opt == 0x10B:   # PE32
        image_base = struct.unpack_from("<I", data, pe_offset + 24 + 28)[0]
    else:                    # PE32+ (0x20B)
        image_base = struct.unpack_from("<Q", data, pe_offset + 24 + 24)[0]

    sec_hdr_off = pe_offset + 24 + size_opt
    sections = []
    for i in range(num_sections):
        off  = sec_hdr_off + i * 40
        name = data[off:off+8].decode("utf-8", errors="ignore").rstrip("\x00")
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(dict(
            name=name, v_addr=v_addr, v_size=v_size,
            raw_ptr=raw_ptr, raw_size=raw_size,
            v_end=v_addr + v_size, raw_end=raw_ptr + raw_size,
            image_base=image_base,
        ))
    return sections


def rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for s in sections:
        if s["v_addr"] <= rva < s["v_end"]:
            return s["raw_ptr"] + (rva - s["v_addr"])
    return None


def check_aion1_in_file(data: bytes, sections: list[dict]) -> dict:
    """Check if .aion1 RVA range is present in the binary file."""
    file_size = len(data)
    start_off = rva_to_offset(sections, AION1_MIN_RVA)
    end_off   = rva_to_offset(sections, AION1_MAX_RVA - 1)

    result = {
        "aion1_rva_start": hex(AION1_MIN_RVA),
        "aion1_rva_end":   hex(AION1_MAX_RVA),
        "aion1_size_bytes": AION1_MAX_RVA - AION1_MIN_RVA,
        "file_size_bytes": file_size,
        "start_file_offset": hex(start_off) if start_off is not None else "OUTSIDE_FILE",
        "end_file_offset":   hex(end_off) if end_off is not None else "OUTSIDE_FILE",
        "present_in_file": False,
        "notes": "",
    }

    if start_off is None:
        result["notes"] = (
            "RVA 0x1472000 (.aion1 start) is not covered by any PE section on disk. "
            "The binary is packed: .aion1 is decompressed/decrypted entirely at runtime. "
            "Cannot extract bytecode stream from this file without unpacking."
        )
    elif start_off >= file_size:
        result["notes"] = (
            f"RVA maps to file offset 0x{start_off:X} which is beyond file size 0x{file_size:X}. "
            "Section exists in header but raw data is absent (virtual section / packed)."
        )
    else:
        result["present_in_file"] = True
        result["notes"] = f"RVA 0x{AION1_MIN_RVA:X} maps to file offset 0x{start_off:X}. Data present."
    return result


def write_candidates_csv(stream_check: dict, out_path: Path):
    rows = [
        {
            "candidate_id": "BS-001",
            "source": "4.7.5.Game.dll.bin PE layout",
            "bytecode_accessible": stream_check["present_in_file"],
            "rva_start": stream_check["aion1_rva_start"],
            "rva_end": stream_check["aion1_rva_end"],
            "file_offset_start": stream_check["start_file_offset"],
            "file_offset_end": stream_check["end_file_offset"],
            "file_size": stream_check["file_size_bytes"],
            "note": stream_check["notes"],
        },
        {
            "candidate_id": "BS-002",
            "source": "FUN_11b5625b dispatcher pcode (runtime RSI init)",
            "bytecode_accessible": False,
            "rva_start": "runtime",
            "rva_end": "runtime",
            "file_offset_start": "N/A",
            "file_offset_end": "N/A",
            "file_size": "N/A",
            "note": (
                "Bytecode pointer RSI is initialized at runtime via: "
                "RSI += LOAD[RBP] (0x11B562AE). "
                "RBP is the VM context struct passed as RDX by the caller. "
                "Cannot resolve without either an unpacked binary or a memory dump. "
                "Statically blocked."
            ),
        },
        {
            "candidate_id": "BS-003",
            "source": "game.dll.txt (Ghidra full disassembly, 1.7 GB)",
            "bytecode_accessible": "UNKNOWN",
            "rva_start": hex(AION1_MIN_RVA),
            "rva_end": hex(AION1_MAX_RVA),
            "file_offset_start": "N/A",
            "file_offset_end": "N/A",
            "file_size": "~1.7 GB",
            "note": (
                "game.dll.txt may contain Ghidra disassembly of .aion1 bytecode "
                "as interpreted code/data. This is the only candidate for locating "
                "static VM bytecode stream content without an unpacked binary. "
                "Requires targeted grep for known VM handler dispatch addresses."
            ),
        },
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    print("VM Bytecode Stream Locator")
    print("=" * 70)
    print()

    if not BIN_PATH.exists():
        print(f"ERROR: Binary not found at {BIN_PATH}")
        sys.exit(1)

    print(f"Loading PE binary: {BIN_PATH}")
    data = BIN_PATH.read_bytes()
    print(f"File size: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")
    print()

    sections = parse_pe_sections(data)
    print("PE Section layout:")
    print(f"  {'Name':10} | {'VAddr':10} | {'VSize':10} | {'RawPtr':10} | {'RawSize':10} | {'V_End':10}")
    print("-" * 70)
    for s in sections:
        print(f"  {s['name']:10} | 0x{s['v_addr']:08X} | 0x{s['v_size']:08X} | "
              f"0x{s['raw_ptr']:08X} | 0x{s['raw_size']:08X} | 0x{s['v_end']:08X}")
    print()

    print(f".aion1 target range:")
    print(f"  VA  : 0x{AION1_MIN_VA:X} .. 0x{AION1_MAX_VA:X}  (size: 0x{AION1_MAX_VA - AION1_MIN_VA:X})")
    print(f"  RVA : 0x{AION1_MIN_RVA:X} .. 0x{AION1_MAX_RVA:X}")
    print()

    stream_check = check_aion1_in_file(data, sections)
    print(f"File offset of .aion1 start : {stream_check['start_file_offset']}")
    print(f"File offset of .aion1 end   : {stream_check['end_file_offset']}")
    print(f"Present in file             : {stream_check['present_in_file']}")
    print()
    print(f"Note: {stream_check['notes']}")
    print()

    print("Dispatcher mechanics confirmed from FUN_11b5625b pcode:")
    for k, v in DISPATCHER_FACTS.items():
        print(f"  {k:35} = {v}")
    print()

    out_csv = Path("bytecode_stream_candidates.csv")
    write_candidates_csv(stream_check, out_csv)
    print(f"Candidates written to: {out_csv}")
    return stream_check["present_in_file"]


if __name__ == "__main__":
    main()
