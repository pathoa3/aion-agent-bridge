import csv
from pathlib import Path

def main():
    handlers_csv = Path(r"C:\AionTools\aion-agent-bridge\artifacts\pass610_antigravity_vm_table_handlers.csv")
    out_csv = Path(r"C:\AionTools\aion-agent-bridge\artifacts\pass610_antigravity_vm_handler_classification.csv")
    
    rows = []
    with open(handlers_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            h_va = r["handler_va"]
            cnt = int(r["occurrence_count"])
            notes = r["notes"]
            first = notes.split("First: ")[1].split(" (")[0] if "First: " in notes else ""
            
            # Map classes systematically
            cls = "unknown"
            if "JMP" in first:
                cls = "branch_dispatch"
            elif "BT" in first or "BTR" in first or "BTS" in first:
                cls = "shift_rotate"
            elif "ADD" in first or "SBB" in first or "SUB" in first or "NEG" in first or "INC" in first or "DEC" in first:
                cls = "add_sub"
            elif "ROR" in first or "RCL" in first or "SHRD" in first or "SHLD" in first or "BSWAP" in first or "ROL" in first or "RCR" in first:
                cls = "shift_rotate"
            elif "NOT" in first or "XOR" in first or "AND" in first or "OR" in first:
                cls = "xor"
            elif "SET" in first:
                cls = "constant_load"
            elif "MOV" in first or "LEA" in first:
                cls = "pointer_update"
                
            rows.append({
                "handler_va": h_va,
                "occurrence_count": cnt,
                "first_instruction": first,
                "classification": cls,
                "notes": notes
            })
            
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["handler_va", "occurrence_count", "first_instruction", "classification", "notes"])
        for r in rows:
            writer.writerow([r["handler_va"], r["occurrence_count"], r["first_instruction"], r["classification"], r["notes"]])
            
    print("pass610_antigravity_vm_handler_classification.csv written.")

if __name__ == "__main__":
    main()
