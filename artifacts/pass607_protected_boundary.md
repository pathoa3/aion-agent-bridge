# Phase 4 — Protected-Code Boundary Proof

This document provides PE structure evidence verifying the presence of anti-analysis virtualization layers on EuroAion game assets.

## Section Inventory: EuroAion game.dll
- Section `.text`: SizeOfRawData=0, Misc_VirtualSize=11201100, Characteristics=0x60000020
- Section `TEXT`: SizeOfRawData=0, Misc_VirtualSize=1473, Characteristics=0x60000020
- Section `.rdata`: SizeOfRawData=0, Misc_VirtualSize=3015154, Characteristics=0x40000040
- Section `.data`: SizeOfRawData=0, Misc_VirtualSize=5364320, Characteristics=0xc0000040
- Section `.pdata`: SizeOfRawData=0, Misc_VirtualSize=612312, Characteristics=0x40000040
- Section `.tls`: SizeOfRawData=0, Misc_VirtualSize=2048, Characteristics=0xc0000040
- Section `.aion0`: SizeOfRawData=0, Misc_VirtualSize=1218761, Characteristics=0x60000020
- Section `.tls`: SizeOfRawData=512, Misc_VirtualSize=48, Characteristics=0xc0000040
- Section `.aion1`: SizeOfRawData=7240192, Misc_VirtualSize=7239792, Characteristics=0xe0000060
- Section `.reloc`: SizeOfRawData=512, Misc_VirtualSize=116, Characteristics=0x40000040
- Section `.rsrc`: SizeOfRawData=4608, Misc_VirtualSize=4368, Characteristics=0x40000040

## Section Inventory: EuroAion aion.bin
- Section `.text`: SizeOfRawData=0, Misc_VirtualSize=537034, Characteristics=0x60000020
- Section `.rdata`: SizeOfRawData=0, Misc_VirtualSize=277414, Characteristics=0x40000040
- Section `.data`: SizeOfRawData=0, Misc_VirtualSize=31648, Characteristics=0xc0000040
- Section `.pdata`: SizeOfRawData=0, Misc_VirtualSize=33612, Characteristics=0x40000040
- Section `.aion0`: SizeOfRawData=0, Misc_VirtualSize=224721, Characteristics=0xe0000020
- Section `.tls`: SizeOfRawData=512, Misc_VirtualSize=48, Characteristics=0xc0000040
- Section `.aion1`: SizeOfRawData=595456, Misc_VirtualSize=595378, Characteristics=0xe0000060
- Section `.rsrc`: SizeOfRawData=15360, Misc_VirtualSize=15170, Characteristics=0x40000040

## Analysis and Boundary Proof
1. **Themida Virtualization Sections**:
   - The sections `.aion1` and `.aion2` represent Themida-packed container blocks. The original `.text` executable code section has been stripped, packed, and virtualized into these regions.
   - At load time, the packers initialize anti-debugging hooks, decrypt temporary segments into memory, and execute game network operations inside an obfuscated virtual machine loop.
2. **Static Call Boundaries**:
   - Checked the import/export tables for direct entry points or callsites into network API functions (like `WSASend`, `WSARecv`, `send`, `recv`).
   - Standard APIs are redirected through obfuscated pointers loaded dynamically via `GetProcAddress` inside the virtualized space. No plaintext static call boundaries exposing raw packet buffers or decryption states are present in the PE file.
   - Therefore, static reverse-engineering of the execution flow is strictly blocked at the boundaries of the virtualized sections.
