"""
extract_vm_entry_context.py
===========================
Static/offline extraction of the VM entry context before the dispatcher loop.

Phases traced:
  1. Network loop entry: FUN_11b45846 -> 11b566dd -> 11b566b4.
  2. Context setup: 11b566b4 preserves RBP and jumps to 11b56999.
  3. Context registration: 11b56999 sets RBP = RDI and jumps to thunk 11b56075 -> 11b59337.
  4. Argument mapping: 11b59337 maps RBP = RDX (the 2nd x64 calling convention argument)
     and thunks to dispatcher entry 11b59832 / 11b59838.
  5. Dispatcher PC fetch: 11b5625b loads bytecode PC offset from qword ptr [RBP] and adds to RSI.
  6. Opcode decryption: raw byte is fetched from [RSI] and decrypted using BL (RBX register).
"""

from __future__ import annotations

import sys
from pathlib import Path

def main():
    print("EuroAion VM Entry Context Extraction")
    print("====================================")
    
    # Trace VM context initialization path
    print("1. Receive path: FUN_11b45846 thunks to 0x11B566DD.")
    print("2. Launch entry: 0x11B566DD JMPs to 0x11B566B4 (inside FUN_11b45846 block).")
    print("   Code at 0x11B566B4:")
    print("     PUSH RBP")
    print("     JMP 0x11b56999")
    print()
    
    print("3. Context copy phase 1: 0x11B56999 (inside FUN_11b56999).")
    print("   Code at 0x11B569A7:")
    print("     MOV RBP, RDI   (Saves RDI into RBP)")
    print("     JMP 0x11b56075  (thunk_FUN_11b59337)")
    print()
    
    print("4. Context copy phase 2: 0x11B59337 (inside FUN_11b59337).")
    print("   Code at 0x11B59343:")
    print("     MOV RBP, RDX   (Overwrites RBP with RDX - the second function parameter)")
    print("     JMP 0x11b59832  (dispatcher wrapper thunk)")
    print()
    
    print("5. Dispatcher entry: FUN_11b5625b (dispatcher).")
    print("   Code at 0x11B562AE:")
    print("     ADD RSI, qword ptr [RBP]   (Initializes/updates RSI bytecode pointer from RBP PC offset)")
    print("   Code at 0x11B562BD:")
    print("     MOV AL, byte ptr [RSI]     (Fetches next bytecode byte)")
    print("   Code at 0x11B562CC:")
    print("     SUB AL, BL                 (Decrypts bytecode opcode using BL register)")
    print()
    
    print("Summary of Mapped Entry Context:")
    print("  - VM Context Pointer (RBP)      <- Initialized from RDX (2nd function parameter)")
    print("  - VM PC Offset ([RBP+0x00])     <- Loaded from VM Context frame")
    print("  - VM Bytecode Pointer (RSI)     <- Initialized from Bytecode Base + VM PC Offset")
    print("  - Decryption Key Register (BL)  <- Passed directly from the caller in RBX register")
    print("  - VM Handler Table Base (R12)   <- Initialized to 0x11B54E6F")

if __name__ == "__main__":
    main()
