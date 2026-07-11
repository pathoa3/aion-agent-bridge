# vm_model_notes.py
# Reconstructed VM Execution Model constants and formulas

TABLE_BASE = 0x11B54E6F
ADD_CONST = 0x15F664FE
IMAGE_BASE = 0x10000000

def rol8(val, count):
    val = val & 0xff
    count = count % 8
    return ((val << count) | (val >> (8 - count))) & 0xff

def decode_opcode(raw, bl):
    # opcode = rol8(((raw - BL + 0x86) ^ 0x34), 5)
    inner = ((raw - bl + 0x86) ^ 0x34) & 0xff
    opcode = rol8(inner, 5)
    new_bl = (bl - opcode) & 0xff
    return opcode, new_bl

def get_handler_va(opcode, raw_table_i64):
    return (raw_table_i64 + ADD_CONST) & 0xffffffffffffffff
