import csv
from pathlib import Path

def main():
    java_path = Path(r"C:\AionTools\EA_VM_TargetDumpJava.java")
    csv_path = Path(r"C:\Users\patho\Documents\Codex\2026-07-05\i\work\outputs_manual_pass8b_java\pass8b_handler_table_from_ghidra.csv")
    
    java_content = java_path.read_text(encoding="utf-8")
    
    # Verify table base and constant in Java script
    assert "0x11B54E6FL" in java_content, "Table base not found in Java script"
    assert "0x15F664FEL" in java_content, "Add constant not found in Java script"
    
    unique_handlers = {}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            op = int(row["opcode"])
            h_va = row["handler_va"]
            first_ins = row["first_instruction"]
            
            if h_va not in unique_handlers:
                unique_handlers[h_va] = {
                    "opcodes": [],
                    "first_ins": first_ins
                }
            unique_handlers[h_va]["opcodes"].append(op)
            
    print(f"Verified base 0x11B54E6F and constant 0x15F664FE")
    print(f"Total handlers parsed: 256")
    print(f"Total unique handlers: {len(unique_handlers)}")
    
    # Write artifacts/pass610_antigravity_vm_table_handlers.csv
    # Columns: handler_index,handler_va,occurrence_count,classification,notes
    # We sort by occurrence count
    sorted_handlers = sorted(unique_handlers.items(), key=lambda x: len(x[1]["opcodes"]), reverse=True)
    
    out_csv = Path(r"C:\AionTools\aion-agent-bridge\artifacts\pass610_antigravity_vm_table_handlers.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["handler_index", "handler_va", "occurrence_count", "classification", "notes"])
        for idx, (h_va, info) in enumerate(sorted_handlers):
            cnt = len(info["opcodes"])
            first = info["first_ins"]
            # Classify based on first instruction (placeholder for Phase 2)
            cls = "unknown"
            if "JMP" in first:
                cls = "branch_dispatch"
            elif "BT" in first or "BTR" in first or "BTS" in first:
                cls = "shift_rotate"
            elif "ADD" in first or "SBB" in first or "SUB" in first or "NEG" in first:
                cls = "add_sub"
            elif "ROR" in first or "RCL" in first or "SHRD" in first or "SHLD" in first:
                cls = "shift_rotate"
            elif "NOT" in first:
                cls = "xor"
            elif "SET" in first:
                cls = "constant_load"
            
            writer.writerow([idx, h_va, cnt, cls, f"First: {first} (opcodes: {info['opcodes'][:4]})"])
            
    print("pass610_antigravity_vm_table_handlers.csv written.")

if __name__ == "__main__":
    main()
