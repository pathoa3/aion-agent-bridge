# Pass607 Codex Lobby Sequential Key-State Summary

- Git-safe summary only; detailed trial rows are local-only.
- raw payload committed: false
- payload hash committed: false
- lobby seed: `73 5A 12 08`
- strict C2S data intermediates before 8745: 30
- C2S data packets through first target 8745: 31
- target packets tested: 8745, 8844, 8974
- sequential state tested: yes
- update rules tested: A, B, C, D, E, F, G, H
- offsets tested: 0, 2, 4, 6, 8
- local-only trial rows: 3360
- exact UTF-16LE KXBOOT matches: 0
- matched message labels: (none)
- best candidate label: formula_a9ea2bc5_tail_00000000
- best update rule: G
- best transform: decXORPass_then_Blowfish offset=0
- best score: 12.574
