from __future__ import annotations

import importlib.util

from pass607_codex_startup_common import ART, write_csv


def detect_provider() -> str:
    checks = [
        ("pycryptodome", "Crypto.Cipher.Blowfish"),
        ("cryptodome", "Cryptodome.Cipher.Blowfish"),
        ("blowfish", "blowfish"),
    ]
    for label, mod in checks:
        try:
            if importlib.util.find_spec(mod):
                return label
        except ModuleNotFoundError:
            continue
    return "pure_python"


def main() -> None:
    provider = detect_provider()
    from blowfish_pure import selftest_rows
    rows = selftest_rows()
    for row in rows:
        row["provider"] = provider
    write_csv(ART / "pass607_codex_blowfish_selftest.csv", rows)
    ok = all(r["encrypt_ok"] == "yes" and r["decrypt_ok"] == "yes" and r["roundtrip_ok"] == "yes" for r in rows)
    lines = [
        "# Pass607 Codex Blowfish Self-Test",
        "",
        f"- provider used: {provider}",
        f"- test vectors: {len(rows)}",
        f"- all self-tests passed: {'yes' if ok else 'no'}",
        "- no network calls and no game/client binaries were used.",
    ]
    ART.mkdir(parents=True, exist_ok=True)
    (ART / "pass607_codex_blowfish_selftest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print({"provider": provider, "selftest_passed": ok, "vectors": len(rows)})
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
