# Agent Protocol

## Purpose

This repository is a shared blackboard between ChatGPT, Antigravity, OpenClaw, Jules, Codex, Ollama, and local scripts.

It is not artifact storage. It only stores sanitized coordination material.

## Roles

| Agent | Role |
|---|---|
| ChatGPT | Human-facing supervisor and task designer |
| Antigravity | Web/acquisition search worker |
| OpenClaw | Browser/search/report worker if available |
| Jules | GitHub file/PR worker if available |
| Codex | Local code/static-analysis worker |
| Ollama | Cheap local reviewer/summarizer |

## Hard guardrails

Never request, perform, or document:

- live process memory dumping
- debugger attachment
- injection
- anti-cheat bypass
- packet injection
- bot/hack offset work
- running unknown binaries

Allowed work is static/offline:

- public web/source search
- source review
- offline PCAP parsing
- static binary triage of files the user provides locally
- candidate classification
- report writing

## Report workflow

1. Worker reads `/state/current_status.json`, `/state/accepted_baseline.md`, `/state/guardrails.md`, and the next task in `/outbox/`.
2. Worker writes result to `/inbox/<agent>_report.md` or a pass-specific file under `/artifacts/`.
3. Supervisor updates `/outbox/supervisor_decision.json` and next tasks.

## Required report fields

Every worker report must include:

```markdown
# Agent report

## Task

## Result
artifact_obtained: yes/no

## Candidates
| classification | URL/source | artifact | downloadable | reason |
|---|---|---|---|---|

## Obtained files
None / sanitized local path list only

## Recommended next action
archive / manual_download / codex_static_triage / continue_search

## Guardrails
No live process, debugger, memory dump, injection, anti-cheat bypass, or packet injection.
```

## Success condition

Do not claim decoder success unless local outputs contain:

- `outbox/decoded_cleartext.txt`
- `outbox/decoder_success.json`
- exact oracle match against Pass574 known plaintext
