# Pass622 Ghidra Jython exporter for native S2C receive/world-handshake path.
# Run inside Ghidra headless. Output is local-only and may contain p-code/disassembly.

from __future__ import print_function
import os
import re
import json

from ghidra.program.model.symbol import RefType
from ghidra.util.task import ConsoleTaskMonitor

NETWORK_NAMES = [
    "recv", "WSARecv", "recvfrom", "send", "WSASend", "closesocket",
    "connect", "select", "ioctlsocket", "InternetReadFile", "ReadFile"
]
VM_ANCHORS = [
    "0x11B562BD", "0x11B5630F", "0x11B5932F", "0x11B57796",
    "0x11B55DF6", "0x11B54E6F", "0x11B566B4", "0x11B56C63"
]
MAX_DEPTH = 3

args = getScriptArgs()
out_dir = args[0] if args else r"C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports"
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

monitor = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()
sm = currentProgram.getSymbolTable()
rm = currentProgram.getReferenceManager()
listing = currentProgram.getListing()

try:
    decomp_available = True
    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
except Exception:
    decomp_available = False
    decomp = None

try:
    from ghidra.app.decompiler.component import DecompilerUtils
except Exception:
    pass


def addr_text(addr):
    return "0x" + addr.toString().upper()


def fn_key(fn):
    return addr_text(fn.getEntryPoint())


def get_function_at_or_containing(addr):
    fn = fm.getFunctionAt(addr)
    if fn is None:
        fn = fm.getFunctionContaining(addr)
    return fn


def symbols_named(name):
    out = []
    syms = sm.getSymbols(name)
    while syms.hasNext():
        out.append(syms.next())
    return out


def refs_to_symbol(sym):
    refs = []
    it = rm.getReferencesTo(sym.getAddress())
    while it.hasNext():
        refs.append(it.next())
    return refs


def callers_of(fn):
    callers = []
    refs = rm.getReferencesTo(fn.getEntryPoint())
    while refs.hasNext():
        ref = refs.next()
        f = get_function_at_or_containing(ref.getFromAddress())
        if f is not None:
            callers.append(f)
    return callers


def callees_of(fn):
    callees = []
    body = fn.getBody()
    ins = listing.getInstructions(body, True)
    while ins.hasNext():
        inst = ins.next()
        flows = inst.getFlows()
        if flows:
            for a in flows:
                f = get_function_at_or_containing(a)
                if f is not None:
                    callees.append(f)
    return callees


def walk(seed_fns, direction):
    seen = {}
    queue = []
    for fn in seed_fns:
        if fn is not None:
            queue.append((fn, 0))
    while queue:
        fn, depth = queue.pop(0)
        key = fn_key(fn)
        if key in seen and seen[key] <= depth:
            continue
        seen[key] = depth
        if depth >= MAX_DEPTH:
            continue
        next_fns = callers_of(fn) if direction == "callers" else callees_of(fn)
        for nxt in next_fns:
            queue.append((nxt, depth + 1))
    return seen


def contains_anchor(fn):
    body = fn.getBody()
    text = str(fn.getName()) + " " + addr_text(fn.getEntryPoint())
    ins = listing.getInstructions(body, True)
    while ins.hasNext():
        inst = ins.next()
        text += " " + addr_text(inst.getAddress()) + " " + inst.toString()
    hits = []
    for a in VM_ANCHORS:
        if a.upper().replace("0X", "0x") in text or a[2:].upper() in text.upper():
            hits.append(a)
    return hits


def disasm_text(fn):
    lines = []
    ins = listing.getInstructions(fn.getBody(), True)
    while ins.hasNext():
        inst = ins.next()
        lines.append("%s %s" % (addr_text(inst.getAddress()), inst.toString()))
    return "\n".join(lines)


def pcode_text(fn):
    lines = []
    ins = listing.getInstructions(fn.getBody(), True)
    while ins.hasNext():
        inst = ins.next()
        ops = inst.getPcode()
        for op in ops:
            lines.append("%s %s" % (addr_text(inst.getAddress()), op.toString()))
    return "\n".join(lines)


def decompile_text(fn):
    if not decomp_available:
        return ""
    try:
        res = decomp.decompileFunction(fn, 60, monitor)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC()
    except Exception as exc:
        return "DECOMPILE_ERROR: %s" % exc
    return ""


def write_hints(fn, pcode, disasm):
    hints = []
    combined = (pcode + "\n" + disasm).splitlines()
    for line in combined:
        up = line.upper()
        if "STORE" in up or re.search(r"\bMOV\s+\w+ PTR \[", up):
            pattern = "write"
            if "QWORD" in up or ":8" in up or "(8)" in up:
                pattern = "8-byte-write"
            if "INT_ZEXT" in up or "INT_ADD" in up or "INT_XOR" in up or "INT_MULT" in up:
                pattern += "+key-arithmetic-nearby"
            hints.append({
                "function": fn.getName(),
                "function_entry": fn_key(fn),
                "pattern": pattern,
                "line": line[:240]
            })
    return hints

# Seed from imports and external refs.
seed_functions = {}
import_refs = []
for name in NETWORK_NAMES:
    for sym in symbols_named(name):
        refs = refs_to_symbol(sym)
        for ref in refs:
            fn = get_function_at_or_containing(ref.getFromAddress())
            import_refs.append({
                "api": name,
                "symbol_address": addr_text(sym.getAddress()),
                "from_address": addr_text(ref.getFromAddress()),
                "function": fn.getName() if fn else "",
                "function_entry": fn_key(fn) if fn else ""
            })
            if fn is not None:
                seed_functions[fn_key(fn)] = fn

# Also seed known VM-anchor containing functions, if present.
for anchor in VM_ANCHORS:
    try:
        addr = toAddr(anchor)
        fn = get_function_at_or_containing(addr)
        if fn is not None:
            seed_functions[fn_key(fn)] = fn
    except Exception:
        pass

all_targets = {}
caller_depth = walk(seed_functions.values(), "callers")
callee_depth = walk(seed_functions.values(), "callees")
for fn in seed_functions.values():
    all_targets[fn_key(fn)] = {"fn": fn, "seed": True, "caller_depth": 0, "callee_depth": 0}
for key, depth in caller_depth.items():
    fn = get_function_at_or_containing(toAddr(key))
    all_targets.setdefault(key, {"fn": fn, "seed": False})["caller_depth"] = depth
for key, depth in callee_depth.items():
    fn = get_function_at_or_containing(toAddr(key))
    all_targets.setdefault(key, {"fn": fn, "seed": False})["callee_depth"] = depth

call_edges = []
function_rows = []
write_rows = []
for key in sorted(all_targets.keys()):
    item = all_targets[key]
    fn = item["fn"]
    if fn is None:
        continue
    dtext = disasm_text(fn)
    ptext = pcode_text(fn)
    ctext = decompile_text(fn)
    anchors = contains_anchor(fn)
    base = "%s_%s" % (key.replace("0x", ""), re.sub(r"[^A-Za-z0-9_]+", "_", fn.getName())[:80])
    open(os.path.join(out_dir, base + ".disasm.txt"), "w").write(dtext)
    open(os.path.join(out_dir, base + ".pcode.txt"), "w").write(ptext)
    open(os.path.join(out_dir, base + ".decomp.txt"), "w").write(ctext)
    write_rows.extend(write_hints(fn, ptext, dtext))
    function_rows.append({
        "entry": key,
        "name": fn.getName(),
        "seed": bool(item.get("seed", False)),
        "caller_depth": item.get("caller_depth", ""),
        "callee_depth": item.get("callee_depth", ""),
        "vm_anchor_hits": ";".join(anchors),
        "disasm_file": base + ".disasm.txt",
        "pcode_file": base + ".pcode.txt",
        "decomp_file": base + ".decomp.txt"
    })
    for callee in callees_of(fn):
        call_edges.append({"from_entry": key, "from_name": fn.getName(), "to_entry": fn_key(callee), "to_name": callee.getName()})

open(os.path.join(out_dir, "import_refs.json"), "w").write(json.dumps(import_refs, indent=2, sort_keys=True))
open(os.path.join(out_dir, "candidate_functions.json"), "w").write(json.dumps(function_rows, indent=2, sort_keys=True))
open(os.path.join(out_dir, "call_edges.json"), "w").write(json.dumps(call_edges, indent=2, sort_keys=True))
open(os.path.join(out_dir, "write_hints.json"), "w").write(json.dumps(write_rows, indent=2, sort_keys=True))
open(os.path.join(out_dir, "export_manifest.json"), "w").write(json.dumps({
    "program": currentProgram.getName(),
    "network_names": NETWORK_NAMES,
    "vm_anchors": VM_ANCHORS,
    "max_depth": MAX_DEPTH,
    "candidate_function_count": len(function_rows),
    "write_hint_count": len(write_rows),
    "note": "Local-only p-code/disassembly export. Summarize before committing."
}, indent=2, sort_keys=True))
print("Pass622 S2C receive export wrote %d functions and %d write hints to %s" % (len(function_rows), len(write_rows), out_dir))
