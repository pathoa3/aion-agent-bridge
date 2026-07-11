import struct
from pathlib import Path

# Let's write the VM Emulator skeleton
# Class: VMEmulator
# It decodes opcodes using the rolling BL obfuscator key.

class VMEmulator:
    def __init__(self, bytecode, initial_bl=0):
        self.bytecode = bytecode
        self.bl = initial_bl
        self.rsi = 0 # VIP (offset in bytecode)
        self.opcodes_decoded = []
        
    def rol8(self, val, count):
        val = val & 0xff
        count = count % 8
        return ((val << count) | (val >> (8 - count))) & 0xff
        
    def step(self):
        if self.rsi >= len(self.bytecode):
            return None
        raw = self.bytecode[self.rsi]
        # opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)
        inner = ((raw - self.bl + 0x86) ^ 0x34) & 0xff
        opcode = self.rol8(inner, 5)
        self.bl = (self.bl - opcode) & 0xff
        self.rsi += 1
        self.opcodes_decoded.append(opcode)
        return opcode

# Let's run a test loop with initial BL guesses (0 to 255)
# over a small sample of bytecode from payload
# We know KXSEQ_001 packet is C2S. Length is 28 (including 2 bytes length, 2 bytes opcode).
# If the header is clear, the first 2 bytes are 1c 00 (length = 28) or similar.
# If the payload starts at offset 4, the ciphertext is:
# 89be2f607a58956f740a3691be6b741f1ad5f79d8d2f077e

payload = bytes.fromhex("0cb8afc389be2f607a58956f740a3691be6b741f1ad5f79d8d2f077e")
print("VM Emulator loaded. Payload bytes parsed.")
