from __future__ import annotations

import json

from common import ART, read_csv, write_csv


def main() -> None:
    rows = []
    decision_path = ART / "pass607_decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8")) if decision_path.exists() else {}
    attempts = read_csv(ART / "pass607_decoder_attempts.csv") if (ART / "pass607_decoder_attempts.csv").exists() else []
    target_candidates = read_csv(ART / "pass607_target_static_candidates.csv") if (ART / "pass607_target_static_candidates.csv").exists() else []
    protected = (ART / "pass607_protected_boundary.md").read_text(encoding="utf-8", errors="replace") if (ART / "pass607_protected_boundary.md").exists() else ""
    target_search = (ART / "pass607_target_static_search.md").read_text(encoding="utf-8", errors="replace") if (ART / "pass607_target_static_search.md").exists() else ""
    public = (ART / "pass607_public_control_reconstruction.md").read_text(encoding="utf-8", errors="replace") if (ART / "pass607_public_control_reconstruction.md").exists() else ""
    frames_tested = sorted({f.strip() for row in attempts for f in row.get("frames_tested", "").split(",") if f.strip()})

    def add(issue: str, severity: str, evidence: str, resolution: str) -> None:
        rows.append({"issue": issue, "severity": severity, "evidence": evidence, "resolution": resolution})

    if "Aion 7.5" in public or "Aion 7.5" in "\n".join(row.get("method", "") for row in attempts):
        add("wrong_version_context", "medium", "Prior public-control text labels the control as Aion 7.5 while this branch is Aion 4.6/nearby public reference truthing.", "Treat as stale context label; do not use as EuroAion evidence.")
    if ".aion2" in protected or ".aion2" in target_search:
        add("unsupported_section_name", "medium", "Prior report mentions .aion2, but section inventory shown for target files lists .aion0/.aion1 only.", "Correct new report to .aion0/.aion1 only unless a file actually contains .aion2.")
    if len(target_candidates) == 0:
        add("empty_target_static_candidates", "high", "pass607_target_static_candidates.csv contains only header/no rows.", "Run independent static scan and keep candidate_found=false if still empty.")
    if len(frames_tested) and len(frames_tested) < 15:
        add("decoder_attempts_only_three_frames", "high", f"Prior attempts used frames {','.join(frames_tested)}.", "New decoder attempt harness must test all 15 corrected oracle frames.")
    if decision.get("passive_startup_oracle_needed") is True and "memory dump" in str(decision.get("next_action", "")).lower():
        add("conflicting_forbidden_next_action", "critical", "decision has passive_startup_oracle_needed=true but next_action asks for a clean memory dump.", "Remove memory-dump path; use only file-backed or passive-capture next evidence.")
    if "static impossible" in target_search.lower() or "statically impossible" in protected.lower():
        add("overbroad_static_impossibility_claim", "medium", "Prior text says static recovery is impossible from virtualized sections.", "State narrower file-backed evidence result instead of absolute impossibility.")
    if not rows:
        add("no_material_audit_findings", "info", "No requested inconsistencies detected.", "Proceed with independent run.")

    write_csv(ART / "pass607_codex_audit.csv", rows)
    lines = ["# Pass607 Codex Audit", "", "Audit of pre-existing Pass607 artifacts. This does not accept the old decision as final.", ""]
    for row in rows:
        lines.append(f"## {row['issue']}")
        lines.append(f"- severity: {row['severity']}")
        lines.append(f"- evidence: {row['evidence']}")
        lines.append(f"- resolution: {row['resolution']}")
        lines.append("")
    (ART / "pass607_codex_audit.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"audit findings={len(rows)}")


if __name__ == "__main__":
    main()
