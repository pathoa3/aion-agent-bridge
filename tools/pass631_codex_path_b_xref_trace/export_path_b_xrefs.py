# Ghidra Jython script: targeted Path B xrefs/caller export.
# Output is local-only. Commit only summaries produced by inspect_path_b_callers.py.

from __future__ import print_function
import csv
import json
import os
import re

TARGETS = [
    ("FUN_11b45846", "0x11B45846"),
    ("thunk_FUN_11b45846", "0x11B52CE5"),
    ("entry_or_thunk_1195D94A", "0x1195D94A"),
    ("FUN_11b56999", "0x11B56999"),
    ("FUN_11b59337", "0x11B59337"),
    ("FUN_11b59832", "0x11B59832"),
    ("FUN_11b59838", "0x11B59838"),
    ("FUN_11b566dd", "0x11B566DD"),
    ("dispatcher_FUN_11b5625b", "0x11B5625B"),
]
IMPORTS = ["recv", "WSARecv", "recvfrom", "send", "WSASend", "select", "ioctlsocket", "connect", "closesocket"]
MAX_CONTEXT_LINES = 80

args = getScriptArgs()
out_dir = args[0] if args else r"C:\AionTools\aion_decoder_agent\outbox\pass631_path_b_xrefs"
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
rm = currentProgram.getReferenceManager()
sm = currentProgram.getSymbolTable()

try:
    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
except Exception:
    decomp = None


def addr_text(addr):
    return "0x" + addr.toString().upper()


def fn_at(addr):
    f = fm.getFunctionAt(addr)
    if f is None:
        f = fm.getFunctionContaining(addr)
    return f


def function_body_text(fn):
    rows = []
    if fn is None:
        return ""
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        rows.append("%s %s" % (addr_text(ins.getAddress()), ins.toString()))
    return "\n".join(rows)


def pcode_text(fn):
    rows = []
    if fn is None:
        return ""
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        for op in ins.getPcode():
            rows.append("%s %s" % (addr_text(ins.getAddress()), op.toString()))
    return "\n".join(rows)


def decomp_text(fn):
    if fn is None or decomp is None:
        return ""
    try:
        res = decomp.decompileFunction(fn, 60, monitor)
        if res.decompileCompleted():
            return res.getDecompiledFunction().getC()
    except Exception as exc:
        return "DECOMPILE_ERROR: %s" % exc
    return ""


def callees(fn):
    out = []
    if fn is None:
        return out
    it = listing.getInstructions(fn.getBody(), True)
    while it.hasNext():
        ins = it.next()
        for flow in ins.getFlows():
            cf = fn_at(flow)
            if cf is not None:
                out.append(cf)
    return out


def refs_to_addr(addr):
    out = []
    it = rm.getReferencesTo(addr)
    while it.hasNext():
        ref = it.next()
        caller = fn_at(ref.getFromAddress())
        out.append({
            "target": addr_text(addr),
            "from_address": addr_text(ref.getFromAddress()),
            "caller_entry": addr_text(caller.getEntryPoint()) if caller else "",
            "caller_name": caller.getName() if caller else "",
            "ref_type": str(ref.getReferenceType()),
        })
    return out


def write_file(name, text):
    f = open(os.path.join(out_dir, name), "w")
    f.write(text or "")
    f.close()

function_rows = []
call_rows = []
xref_rows = []
seen = {}

for label, addr_s in TARGETS:
    try:
        addr = toAddr(addr_s)
    except Exception:
        continue
    fn = fn_at(addr)
    if fn is None:
        xref_rows.extend(refs_to_addr(addr))
        continue
    key = addr_text(fn.getEntryPoint())
    seen[key] = fn
    xref_rows.extend(refs_to_addr(addr))
    base = "%s_%s" % (key.replace("0x", ""), re.sub(r"[^A-Za-z0-9_]", "_", fn.getName()))
    write_file(base + ".disasm.txt", function_body_text(fn))
    write_file(base + ".pcode.txt", pcode_text(fn))
    write_file(base + ".decomp.txt", decomp_text(fn))
    function_rows.append({"label": label, "entry": key, "name": fn.getName(), "address_requested": addr_s})
    for callee in callees(fn):
        call_rows.append({"from_entry": key, "from_name": fn.getName(), "to_entry": addr_text(callee.getEntryPoint()), "to_name": callee.getName()})

# Add direct callers of Path B targets and one-level callees around them.
for row in list(xref_rows):
    if row.get("caller_entry"):
        try:
            fn = fn_at(toAddr(row["caller_entry"]))
        except Exception:
            fn = None
        if fn is not None and addr_text(fn.getEntryPoint()) not in seen:
            key = addr_text(fn.getEntryPoint())
            seen[key] = fn
            base = "%s_%s" % (key.replace("0x", ""), re.sub(r"[^A-Za-z0-9_]", "_", fn.getName()))
            write_file(base + ".disasm.txt", function_body_text(fn))
            write_file(base + ".pcode.txt", pcode_text(fn))
            write_file(base + ".decomp.txt", decomp_text(fn))
            function_rows.append({"label": "direct_caller", "entry": key, "name": fn.getName(), "address_requested": ""})
            for callee in callees(fn):
                call_rows.append({"from_entry": key, "from_name": fn.getName(), "to_entry": addr_text(callee.getEntryPoint()), "to_name": callee.getName()})

import_rows = []
for name in IMPORTS:
    syms = sm.getSymbols(name)
    while syms.hasNext():
        sym = syms.next()
        refs = rm.getReferencesTo(sym.getAddress())
        while refs.hasNext():
            ref = refs.next()
            fn = fn_at(ref.getFromAddress())
            import_rows.append({
                "api": name,
                "from_address": addr_text(ref.getFromAddress()),
                "caller_entry": addr_text(fn.getEntryPoint()) if fn else "",
                "caller_name": fn.getName() if fn else "",
            })

for name, rows in (("path_b_functions.csv", function_rows), ("path_b_call_edges.csv", call_rows), ("path_b_xrefs.csv", xref_rows), ("path_b_import_refs.csv", import_rows)):
    if not rows:
        write_file(name, "")
        continue
    path = os.path.join(out_dir, name)
    with open(path, "w") as f:
        w = csv.DictWriter(f, fieldnames=sorted(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

write_file("path_b_manifest.json", json.dumps({
    "targets": TARGETS,
    "imports": IMPORTS,
    "function_count": len(function_rows),
    "xref_count": len(xref_rows),
    "call_edge_count": len(call_rows),
    "import_ref_count": len(import_rows),
    "note": "Local-only targeted Path B xref export. Summarize before commit."
}, indent=2, sort_keys=True))
print("Pass631 Path B xref export wrote %d functions, %d xrefs" % (len(function_rows), len(xref_rows)))
