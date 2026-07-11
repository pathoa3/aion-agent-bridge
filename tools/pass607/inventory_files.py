from __future__ import annotations

from common import ART, EURO, classify_file, parse_pe_sections, sha256, write_csv


def main() -> None:
    rows = []
    for path in sorted(p for p in EURO.rglob("*") if p.is_file()):
        data = path.read_bytes()
        sections = parse_pe_sections(data)
        rows.append({
            "path": str(path),
            "relative_path": str(path.relative_to(EURO)),
            "classification": classify_file(path),
            "size": len(data),
            "sha256": sha256(path),
            "is_pe": "yes" if sections else "no",
            "sections": ";".join(f"{s['name']}:raw={s['raw_size']}:vsize={s['vsize']}:exec={int(bool(s['exec']))}:entropy={float(s['entropy']):.2f}" for s in sections),
        })
    write_csv(ART / "pass607_codex_inventory.csv", rows)
    print(f"inventory rows={len(rows)}")


if __name__ == "__main__":
    main()
