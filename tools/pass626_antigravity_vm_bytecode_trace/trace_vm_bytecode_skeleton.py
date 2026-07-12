"""
trace_vm_bytecode_skeleton.py
=============================
Simulates the VM bytecode instruction execution loop offline.
Loads the Ghidra handler table to resolve opcodes to handler VAs.
Supports simulating bytecode decryption and rolling key updates.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

# Dispatcher opcode decode helper
def rol8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF

def decode_opcode(raw: int, bl: int) -> int:
    return rol8(((raw - bl + 0x86) ^ 0x34), 5)

def update_bl(bl: int, decoded_opcode: int) -> int:
    return (bl - decoded_opcode) & 0xFF

def load_handler_table(csv_path: Path) -> dict[int, tuple[str, str]]:
    """Map opcode -> (handler_va, first_instruction)."""
    table = {}
    if not csv_path.exists():
        return table
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            op = int(row["opcode"])
            h_va = row["handler_va"]
            first_ins = row["first_instruction"]
            table[op] = (h_va, first_ins)
    return table

def main():
    # Paths
    here = Path(__file__).parent
    inbox_dir = Path(r"C:\AionTools\aion_decoder_agent\inbox")
    table_csv = inbox_dir / "pass8b_handler_table_from_ghidra.csv"
    
    print("VM Bytecode Execution Trace Simulator")
    print("=" * 80)
    
    # Load VM handler table mapping
    handler_table = load_handler_table(table_csv)
    if not handler_table:
        print("WARNING: pass8b_handler_table_from_ghidra.csv not found in inbox!")
        print("Continuing with offline skeleton simulation...")
    else:
        print(f"Loaded {len(handler_table)} handler mappings from Ghidra export.")
    print()
    
    # Placeholder bytecode segment (first 16 bytes of S2C initialization bytecode from .aion1)
    # Since S2C initial key is not found yet, we set a mock encrypted bytecode stream for testing
    mock_bytecode = bytes([0xc1, 0x66, 0x83, 0xf7, 0xd5, 0x26, 0x5d, 0xd3, 0x7c, 0x0c, 0xd5])
    
    # Simulated initial register states
    initial_bl = 0xCA  # Implied length mask low byte as a test starting BL
    pc_offset = 0
    bl = initial_bl
    
    print(f"Simulation configuration:")
    print(f"  Initial BL/RBX  : 0x{bl:02X}")
    print(f"  Bytecode Size   : {len(mock_bytecode)} bytes")
    print("-" * 80)
    
    print(f"{'PC_Offset':9} | {'Raw_Byte':8} | {'Dec_Opcode':10} | {'Handler_VA':12} | {'First_Ins':20} | {'Next_BL':7}")
    print("-" * 80)
    
    for idx, raw in enumerate(mock_bytecode):
        decoded = decode_opcode(raw, bl)
        next_bl = update_bl(bl, decoded)
        
        # Look up handler VA
        h_va, first_ins = handler_table.get(decoded, ("unknown_va", "unknown_ins"))
        
        print(f"0x{idx:04X}     | 0x{raw:02X}     | 0x{decoded:02X}       | {h_va} | {first_ins[:20]:20} | 0x{next_bl:02X}")
        
        bl = next_bl

if __name__ == "__main__":
    main()
