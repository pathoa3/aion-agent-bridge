# Guardrails

## Forbidden

- live process memory dump
- debugger attachment
- injection
- anti-cheat bypass
- packet injection
- bot/hack/offset branches
- running unknown binaries
- uploading raw captures or game binaries to this repo
- committing API keys, cookies, tokens, `.env`, credentials

## Allowed

- static/offline analysis
- source review
- public web acquisition search
- candidate classification
- sanitized summaries
- hashes and file names
- local paths only when useful and non-sensitive

## Success claims

No worker may claim decoder success unless exact oracle UTF-16LE messages are recovered and validated against Pass574 known plaintext.
