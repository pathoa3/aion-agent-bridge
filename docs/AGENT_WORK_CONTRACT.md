# Agent Work Contract

This contract is the permanent operating baseline for Codex work in this repository. Every future pass prompt is a delta against this file. Apply it exactly unless a later committed revision explicitly changes it.

## 1. Precedence and source of truth

1. Start from the latest `main` commit.
2. Inspect, in this order:
   - `inbox/codex_report.md`
   - the newest `artifacts/pass*_decision.json`
   - the newest `artifacts/pass*_summary.md`
   - the newest `artifacts/pass*_work_queue.json`
   - artifacts and tools directly referenced by those files
3. Latest `main` overrides handovers, copied prompts, screenshots, and older local notes.
4. Do not restart completed research, repeat a closed branch, or produce a broad historical recap.
5. Continue from the latest unresolved blocker only.
6. Do not rescan unrelated files when current artifacts already identify the relevant inputs.

## 2. Project objective

Build a reproducible offline extractor/decoder for passive EuroAion Aion 4.6 chat captures. Success requires exact visible chat recovery and independent validation, not merely timing correlation, candidate framing, high scores, plausible structure, or generated files.

## 3. Allowed scope

Allowed:

- passive captures made by the user;
- offline PCAP/PCAPNG parsing and TCP reassembly;
- deterministic framing, format, transform, compression, and encoding analysis;
- static inspection of already-existing binaries, reports, scripts, decompiler exports, and disassembly exports;
- creation and execution of offline parsers and bounded analysis scripts;
- local-only detailed analysis in `C:\AionTools\aion_decoder_agent`;
- Git-safe high-level tools, summaries, aggregate metrics, decisions, and reproducibility metadata.

Forbidden:

- executing unknown game binaries;
- attaching to or debugging a live process;
- injection, hooking, patching, or modifying the client;
- manipulating or injecting live network traffic;
- anti-cheat bypass work;
- bot or gameplay-automation tooling;
- dynamic unpacking of the running client;
- committing private captures, packet contents, packet hashes, raw/decoded byte blobs, ciphertext blobs, keys, masks, anchors, binaries, DLLs, EXEs, archives, credentials, tokens, or secrets.

Exact session keys, masks, anchors, and private payload bytes must remain local and must never be quoted in reports, prompts, chat, or Git.

## 4. Fixed local paths and data policy

Repository:

```text
C:\AionTools\aion-agent-bridge
```

Decoder workspace:

```text
C:\AionTools\aion_decoder_agent
```

Default current capture:

```text
C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng
```

Default known-message source:

```text
C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt
```

Detailed/private intermediate outputs belong under:

```text
C:\AionTools\aion_decoder_agent\outbox\passXXX_*
```

Only safe aggregate artifacts and reproducible code may be committed.

## 5. Authoritative timing policy

1. Game-generated `chat.log` rows are the only authoritative visible-message timestamps.
2. Manual marker-script timestamps are execution notes only and must never be used for scoring or preferred over `chat.log`.
3. A whole-second `chat.log` time represents the interval `.000` through `.999`.
4. Primary correlation uses that exact one-second interval.
5. Fallback windows may use ±1.5 seconds, then ±3 seconds, then ±5 seconds, and must be labeled as fallbacks.
6. Exact chat text from `chat.log` must be used when available; do not reconstruct text or lengths from screenshots.
7. Mixed old/new marker logs must be filtered explicitly without deleting the source.

## 6. Dynamic flow policy

1. Never hardcode a previously observed world port.
2. Detect the current world flow from the capture as the long-lived, high-volume server flow in the expected world-port range after login.
3. Record the detected flow and the evidence used.
4. Treat port `10242` as heartbeat/control or timing aid unless new deterministic parser evidence proves content transport.
5. Do not reopen a closed flow role from timing correlation alone.

## 7. Pass construction

Every pass must have one precise blocker and one connected objective. A pass must not be a collection of unrelated investigations.

Each pass must create:

```text
tools/passXXX_<name>/
artifacts/passXXX_<name>_*.csv
artifacts/passXXX_<name>_decision.json
artifacts/passXXX_<name>_summary.md
artifacts/passXXX_work_queue.json
inbox/codex_report.md
```

The pass directory must include a single master runner that executes or resumes the complete queue.

## 8. Persistent work queue

1. Create the queue before substantive execution.
2. Each stage records at least:
   - name;
   - script/command;
   - status: `pending`, `running`, `completed`, or `blocked`;
   - attempts;
   - primary result;
   - fallback definition;
   - fallback status;
   - last error;
   - produced artifacts.
3. Save queue state before and after every stage and fallback.
4. Resume completed work; do not rerun it unless input or code changed and the reason is recorded.
5. For every stage:
   - run the primary method;
   - if blocked or inconclusive, run the predefined fallback;
   - save state;
   - continue to the next unfinished stage.
6. `blocked` is not completion.
7. The final response is forbidden while any stage or required fallback is `pending`, `running`, or unresolved.
8. A failure in one branch must not stop independent remaining stages.
9. Do not create artificial work to consume time. Exhaustiveness means completing the defined bounded methods and controls.

## 9. Substantive-work rule

Creating scaffolding, CSV headers, candidate rankings, or scripts without executing them is not substantive completion.

Where applicable, the pass must include:

- complete bounded model/search grid rather than a tiny sample;
- actual TCP stream reconstruction with sequence-aware handling where available;
- complete candidate parser generation;
- execution of every generated parser;
- body extraction/transform logic, not only frame splitting or size reporting;
- positive controls;
- negative controls from unrelated windows;
- repeated-message cross-validation;
- channel/type cross-validation;
- reproducibility rerun from the master runner;
- explicit accounting for every supported, weakened, closed, or still-open hypothesis.

If a stage claims static parser mapping, it must extract concrete file-backed constraints such as function/address, field offset, width, endianness, length arithmetic, delimiter, transform order, buffer ownership, or dispatch relation. Merely listing artifact paths or generic roles does not count.

## 10. Fallback rule

Every potentially blocking stage must define its fallback before execution. Examples:

- sequence-aware reassembly unavailable → implement TCP sequence extraction from raw packet headers; only then use and label a validated capture-order fallback;
- static export absent → search the existing local inventory/handovers for the exact export, then identify the single missing file/path;
- top framing family inconclusive → expand only adjacent bounded model dimensions justified by evidence;
- parser transform inconclusive → run the bounded transform family and negative controls, then rank exact unmet constraints;
- current capture insufficient only after current framing/transform branches are exhausted → prepare a narrow discriminator capture plan.

Do not ask the user for a file until all work not dependent on that file is complete and the exact missing path is identified.

## 11. Acceptance gate

Do not claim decoder, extractor, parser, framing, transform, channel, or plaintext success unless all applicable conditions pass:

1. exact known visible text is recovered;
2. the match falls in the authoritative `chat.log` interval or a clearly labeled fallback window;
3. at least one repeated occurrence of the same message validates independently;
4. unrelated negative-control windows do not collide;
5. the result is reproducible from the master runner;
6. frame/body boundaries and transform steps are explicit;
7. no manual-note timestamp was used for scoring;
8. no private bytes, keys, masks, or anchors were committed.

A score, probable field, timing match, high-entropy observation, or plausible frame model is evidence only, never acceptance.

## 12. Decision and reporting rules

The decision JSON and summary must state, without ambiguity:

- exact acceptance-gate result;
- current unresolved blocker;
- branches completed and fallbacks run;
- hypotheses supported, weakened, closed, and remaining;
- whether the current capture is still useful;
- whether a new capture is actually required;
- the single best next direction;
- the exact next unblocker or missing input;
- whether any private data was committed.

Never state:

- S2C decoder success without exact known plaintext recovery;
- push success without remote confirmation;
- current-session key/anchor availability without local verification;
- `10242` chat-content transport without deterministic parser evidence;
- valid timing correlation when manual execution notes were used.

## 13. Safe checkpoint and push

Before checkpointing, ensure `tools/agent_helpers/agent_safe_checkpoint.ps1` allowlists:

```text
docs/AGENT_WORK_CONTRACT.md
tools/agent_helpers/run_work_queue_until_empty.ps1
tools/agent_helpers/work_queue_schema.json
tools/passXXX_*
artifacts/passXXX_*
inbox/codex_report.md
```

Run the pass master runner, then:

```powershell
cd C:\AionTools\aion-agent-bridge
powershell -ExecutionPolicy Bypass -File tools\agent_helpers\agent_safe_checkpoint.ps1 -Message "<meaningful commit message>"
git push origin main
```

The pass is not complete until:

- the master runner completed;
- the queue has no pending/running/unresolved stages;
- every blocked/inconclusive stage completed its fallback;
- every required artifact exists and is non-empty where expected;
- the safe checkpoint completed;
- `git push origin main` returned success;
- the remote `main` commit is verified.

## 14. Delta-prompt policy

After this contract exists, future Codex prompts must contain only the delta:

```text
Apply docs/AGENT_WORK_CONTRACT.md exactly.

Continue from latest main.

PassXXX: <short pass title>

DELTA OBJECTIVE
...

CURRENT SOURCE OF TRUTH
...

NEW EVIDENCE OR CORRECTION
...

CURRENT BLOCKER
...

WORK QUEUE CHANGES
...

REQUIRED SUBSTANTIVE WORK
...

REQUIRED OUTPUTS
...

ACCEPTANCE GATE
...

NO-EARLY-STOP RULE
...

FINAL COMMANDS
...
```

Do not paste this baseline into future prompts. Do not let a delta prompt weaken this contract implicitly; contract changes require an explicit committed edit.
