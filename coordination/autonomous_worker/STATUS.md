# Aion Autonomous Worker Status

Generated: 2026-07-18T23:52:55.8296747+02:00

Repository: pathoa3/aion-agent-bridge
Branch: worker/runtime-status

This status is produced automatically by the isolated Hermes/Gemma worker.
It intentionally excludes raw logs, binaries, checkpoints, captures, configuration
files, credentials, and other large or sensitive artifacts.

## Supervisor heartbeat

{
    "timestamp":  "2026-07-18T23:41:51.4868781+02:00",
    "phase":  "local_cycle",
    "cycle":  3,
    "message":  "",
    "supervisor_pid":  70476,
    "worker_root":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND",
    "project_root":  "C:\\AionTools",
    "hermes_home":  "C:\\Users\\patho\\AppData\\Local\\hermes",
    "local_provider":  "ollama",
    "local_model":  "gemma4:12b",
    "local_endpoint":  "http://localhost:11434/v1",
    "codex_provider":  "openai-codex",
    "codex_model":  "gpt-5.6-sol",
    "command_timeout_seconds":  1800,
    "last_cycle_mode":  "Local",
    "last_cycle_exit":  1,
    "consecutive_failure_count":  2,
    "last_failure_signature":  "Local|ollama|gemma4:12b|http://localhost:11434/v1|System.Management.Automation.RuntimeException: The variable \u0027$timedOut\u0027 cannot be retrieved because it has not been set.\r\n   at System.Management.Automation.ExceptionHandlingOps.CheckActionPreference(FunctionContext funcContext, Exception exception)\r"
}


## Background supervisor

_Not available._

## Last completed Hermes cycle

{
    "timestamp":  "2026-07-18T23:41:41.0719657+02:00",
    "mode":  "Local",
    "exit_code":  1,
    "log":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND\\logs\\local-cycle-20260718_233146.log",
    "hermes":  "C:\\Users\\patho\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\hermes.exe",
    "hermes_home":  "C:\\Users\\patho\\AppData\\Local\\hermes",
    "project_root":  "C:\\AionTools",
    "provider":  "ollama",
    "model":  "gemma4:12b",
    "endpoint":  "http://localhost:11434/v1",
    "result_state":  "failed",
    "failure":  "System.Management.Automation.RuntimeException: The variable \u0027$timedOut\u0027 cannot be retrieved because it has not been set.\r\n   at System.Management.Automation.ExceptionHandlingOps.CheckActionPreference(FunctionContext funcContext, Exception exception)\r\n   at System.Management.Automation.Interpreter.ActionCallInstruction`2.Run(InterpretedFrame frame)\r\n   at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)\r\n   at System.Management.Automation.Interpreter.EnterTryCatchFinallyInstruction.Run(InterpretedFrame frame)"
}


## Current accepted project state

# Current Autonomous Worker State

Directive: operator-20260718-pass665-mapped-game-inventory-v1
Reconciled: 2026-07-18T23:52:00+02:00

## Main project objective

Recover EuroAion's live receive/decryption boundary sufficiently to decode sequential world/chat traffic and feed plaintext chat into the automatic translation pipeline.

## Completed evidence

The null indirect call chain ending at `0x180166797` is integrated and no longer the active worker target:

- `0x180164106: mov rax, qword ptr [rsp]`
- `0x18016410A: push rax`
- `0x18016155E: push qword ptr [rsp + 8]`
- `0x180166792: pop rax`
- `0x180166797: call rax`
- At `0x180166797`, `RAX = 0`.

The bounded P1 experiment is complete:

- stop-before RIP: `0x180164106`;
- `RSP/read address = 0x7000ffdc58`;
- qword value: `0x0`;
- last current-generation write: `0x18016773e: mov qword ptr [rsp], rax`;
- writer `RAX = 0`;
- classification: stack-pivot construction.

## Alignment decision

The H2 follow-up, "trace why `RAX` is already zero at `0x18016773e`", is classified as `3. Low-priority diagnostic tangent`.

Evidence for the classification: P1 already proves the null-call value is stack-pivot construction. Tracing the earlier zero source does not currently produce a mapped runtime `game.dll`, prove Game Winsock IAT slots, prove the active recv/WSARecv hook installer, prove CrySystem/security bootstrap, or recover exact `AegInitEngine` x64 arguments. Pass665/Pass666 are blocked on those main-path artifacts instead.

## Current autonomous-worker supporting task

Run exactly one bounded existing-artifact inventory for Pass665/Pass666:

1. Read existing mapped `game.dll` candidate artifacts only.
2. Hash each candidate and validate PE/image metadata when available.
3. Identify whether the best mapped image is coherent enough for static IAT/xref work.
4. Record missing or unproven mapped pages/ranges that block Game Winsock IAT proof.
5. Preserve one concise durable result under `reports\`.

## Acceptance gate

Stop after writing one durable result that contains candidate path, SHA-256, size, PE validity, image base, image size, section/range summary, and an explicit yes/no answer for whether this artifact unblocks concrete Game Winsock IAT slot validation.

## Escalation condition

Escalate to Codex only if existing artifacts prove contradictory mapped images or a candidate needed for Pass665/Pass666 is absent, unreadable, or requires a new acquisition plan. Do not escalate merely to continue H2 provenance.

## Prohibited actions

- no production or guest-state mutation;
- no invalid-page mapping;
- no seeded values or forced control flow;
- no binary patching, hooks, injection, or live process attachment;
- do not modify or stop `AION_LOCAL_WORKER_V22` or `AION_LOCAL_WORKER_V22_2`;
- do not delete evidence or historical results;
- do not repeat completed P1 or redo the completed broad harness repair.

## Evidence

See `state\EVIDENCE_INDEX.md`.


## Latest local-worker result

# Local Cycle Result

Directive: operator-20260718-pass665-mapped-game-inventory-v1
Status: coordination_reconciled
Time: 2026-07-18T23:52:00+02:00

## Completed evidence retained

Integrated Codex handoff result and bounded P1 result remain accepted:

- `0x180164106: mov rax, qword ptr [rsp]`
- `0x18016410A: push rax`
- `0x18016155E: push qword ptr [rsp + 8]`
- `0x180166792: pop rax`
- `0x180166797: call rax`
- `RAX = 0` at `0x180166797`.
- `RSP/read address = 0x7000ffdc58` before `0x180164106`.
- Last current-generation write to the stack slot: `0x18016773e: mov qword ptr [rsp], rax`, with `RAX = 0`.
- Classification: stack-pivot construction.

## Alignment result

H2 follow-up classification: `3. Low-priority diagnostic tangent`.

## Smallest next action

Run one existing-artifact-only mapped `game.dll` inventory for Pass665/Pass666 and stop after a single durable report.


## Pending Codex request

# Codex Request

Status: no active Codex request.
Reconciled: 2026-07-18T23:52:00+02:00

The previous harness-repair request is obsolete and fulfilled. The active worker target is local-only unless the escalation condition in `state\TASK_QUEUE.md` is met.

Do not continue the retired H2 provenance request unless it supplies a concrete missing runtime image, page, state, call edge, or initializer needed by the live receive/decryption path.


## Latest Codex result

{
  "schema": "aion-h2-call-rax-preblocker-trace-v1",
  "created_unix": 1784379067.0480409,
  "checkpoint": "C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\results_h2\\exception_epochs\\checkpoints\\epoch_001_post_redirect_1801f9e07.aionckpt",
  "checkpoint_sha256": "80c829f236d50e3fbbc6cceb74d49fd4228edfdd8ed79895fa1da06468744ca0",
  "checkpoint_worker": {
    "total": 725424268,
    "api_count": 1218,
    "reason": "post_context_redirect",
    "source": "exception_epoch_runner",
    "diagnostic_label": "DIAGNOSTIC_SLOT_SEED_NOT_PROMOTABLE"
  },
  "metadata_refresh": {
    "changed": true,
    "name": "MessageBoxExA",
    "base": "0x6200800000",
    "address": "0x6200820e40",
    "export_count": 356,
    "slot_refresh": {
      "slot": "0x1801595c5",
      "expected": "0x6200820e40",
      "before": "0x6200820e40",
      "writer": "refresh_user32_messageboxexa_export",
      "python_stack": [
        "  File \"C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\call_rax_preblocker_trace.py\", line 169, in <module>\n    raise SystemExit(main())\n",
        "  File \"C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\call_rax_preblocker_trace.py\", line 68, in main\n    em, worker, meta = restore_checkpoint(CHECKPOINT, make_emulator, expected_hashes(), INPUTS)\n",
        "  File \"C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\durable_checkpoint.py\", line 217, in restore_checkpoint\n    metadata[\"post_restore_contract_refresh\"] = em.refresh_user32_messageboxexa_export()\n",
        "  File \"C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\work\\frozen_v19_loader.py\", line 170, in refresh_user32_messageboxexa_export\n    slot_refresh = self._write_known_messageboxexa_slot(slot)\n",
        "  File \"C:\\AionTools\\AION_SHADOW_API_CONTRACT_MATRIX_V1_12\\h2_exception_epoch_diagnostic\\work\\frozen_v19_loader.py\", line 73, in _write_known_messageboxexa_slot\n    'python_stack': traceback.format_stack(limit=8),\n"
      ],
      "after": "0x6200820e40",
      "changed": false,
      "reason": "refreshed known MessageBoxExA resolver slot after checkpoint restore"
    },
    "known_slot_integrity": {
      "0x1801595c5": {
        "name": "user32.dll!MessageBoxExA",
        "classification": "must remain nonzero after checkpoint restore",
        "qword": "0x6200820e40",
        "ok": true
      },
      "0x180159d1f": {
        "name": "RtlLookupFunctionEntry diagnostic scratch / guest-cleared lifecycle slot",
        "classification": "guest intentionally zero",
        "qword": "0x62004205f0",
        "ok": false
      }
    }
  },
  "restored_historical_exception_dispatches": [
    {
      "phase": "raise",
      "code": "0x40010006",
      "flags": "0x0",
      "caller_rip": "0x1801f9df8",
      "caller_rsp": "0x7000ffde90",
      "handlers": [
        "0x1801f9e46",
        "0x1801d857d"
      ]
    },
    {
      "phase": "handler_return",
      "handler": "0x1801f9e46",
      "result": "0xffffffff",
      "context_rip": "0x1801f9e07",
      "context_rsp": "0x7000ffdec0"
    },
    {
      "generation": 1,
      "phase": "hardware_av_dispatch",
      "code": "0xc0000005",
      "fault_rip": "0x18022131b",
      "fault_rsp": "0x7000ffdea0",
      "fault_address": "0x50003ac000",
      "record": "0x7000ff9ea0",
      "context": "0x7000ff9fa0",
      "context_sha256_before_handlers": "a20a512ed7b8d55ff905a2dd540f9d9a3814ef18c89e3959df520c7622a4a858",
      "pointers": "0x7000ffa5a0",
      "return_stub": "0x60000002c0",
      "handlers_snapshot": [
        {
          "handle": "0x5000182000",
          "first": 1,
          "handler": "0x1801d857d"
        }
      ],
      "scratch": {
        "base": "0x7000ff9ea0",
        "source": "existing_stack_page"
      },
      "exception_record_sha256": "da0092d11999d3664b73f507c6fbd0fc86f474d9524377369de81d971e51dc49"
    }
  ],
  "current_run_exception_dispatches": [],
  "reason": "pre_call_rax",
  "error": "",
  "total": 725476268,
  "pre_call": {
    "rip": "0x180166797",
    "bytes": "ffd0",
    "disassembly": "call rax",
    "registers_before": {
      "rip": "0x180166797",
      "rsp": "0x7000ffdc60",
      "rbp": "0x16d647014",
      "rax": "0x0",
      "rbx": "0xb9867f6f",
      "rcx": "0x0",
      "rdx": "0x1801d7916",
      "rsi": "0x1801d7b0e",
      "rdi": "0x0",
      "r8": "0x180157781",
      "r9": "0x0",
      "r10": "0x7000ffdf40",
      "r11": "0xffffffff",
      "r12": "0x400000",
      "r13": "0x2",
      "r14": "0x0",
      "r15": "0x0",
      "eflags": "0x216"
    },
    "rsp_stack_12_before": [
      {
        "address": "0x7000ffdc60",
        "value": "0x1801d7b0e"
      },
      {
        "address": "0x7000ffdc68",
        "value": "0xffffffff8006678c"
      },
      {
        "address": "0x7000ffdc70",
        "value": "0x0"
      },
      {
        "address": "0x7000ffdc78",
        "value": "0x7000ffdc90"
      },
      {
        "address": "0x7000ffdc80",
        "value": "0x7000ffdc90"
      },
      {
        "address": "0x7000ffdc88",
        "value": "0x7000ffdc90"
      },
      {
        "address": "0x7000ffdc90",
        "value": "0x1801d7b0e"
      },
      {
        "address": "0x7000ffdc98",
        "value": "0x60000002c0"
      },
      {
        "address": "0x7000ffdca0",
        "value": "0x0"
      },
      {
        "address": "0x7000ffdca8",
        "value": "0x0"
      },
      {
        "address": "0x7000ffdcb0",
        "value": "0x0"
      },
      {
        "address": "0x7000ffdcb8",
        "value": "0x0"
      }
    ],
    "slot_state": {
      "0x180159d1f": "0x62004205f0",
      "0x1801595c5": "0x6200820e40"
    },
    "last_relevant_writes": [
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001918",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002745",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001918",
          "rdi": "0x62000027c4",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x620000191c",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002745",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x620000191c",
          "rdi": "0x62000027d1",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001920",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002745",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001920",
          "rdi": "0x62000027e0",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001924",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002745",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001924",
          "rdi": "0x62000027ef",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001928",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002745",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001928",
          "rdi": "0x6200002804",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x620000192c",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x620000192c",
          "rdi": "0x620000281b",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001930",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001930",
          "rdi": "0x620000282f",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001934",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001934",
          "rdi": "0x6200002843",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001938",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001938",
          "rdi": "0x6200002851",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x620000193c",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x620000193c",
          "rdi": "0x6200002869",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001940",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001940",
          "rdi": "0x620000287a",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001944",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001944",
          "rdi": "0x620000288b",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x202"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
        "value": "0x6200001948",
        "rip": "0x18015a4d4",
        "instruction": "push rsi",
        "registers": {
          "rip": "0x18015a4d4",
          "rsp": "0x7000ffdc38",
          "rbp": "0x16d647014",
          "rax": "0x6200002845",
          "rbx": "0x6200000000",
          "rcx": "0x5484",
          "rdx": "0xda6038c2",
          "rsi": "0x6200001948",
          "rdi": "0x6200002898",
          "r8": "0x180157781",
          "r9": "0x0",
          "r10": "0x7000ffdf40",
          "r11": "0xffffffff",
          "r12": "0x400000",
          "r13": "0x2",
          "r14": "0x0",
          "r15": "0x0",
          "eflags": "0x206"
        }
      },
      {
        "address": "0x7000ffdc30",
        "size": 8,
      

_Section truncated by the GitHub reporter._

## Current task queue

# Autonomous Task Queue

Directive: operator-20260718-pass665-mapped-game-inventory-v1

## Completed

- P0 Codex null-RAX chain integration is complete.
- P1 stack-slot writer trace is complete.
- Harness provider/model routing is complete: Local uses `--provider ollama --model gemma4:12b`; Codex uses `--provider openai-codex --model gpt-5.6-sol`.
- Residual strict-mode crash in cycle result capture is fixed by initializing `$timedOut = $false`.

## Current bounded task - Pass665 mapped game image inventory

Perform one existing-artifact-only experiment:

1. Inspect `C:\AionTools\aion_decoder_agent\outbox\pass666_recv_boundary\mapped_game_candidates.csv`.
2. Verify the listed mapped image candidate files still exist and match their recorded SHA-256 values.
3. Validate basic PE/image metadata for the best candidate.
4. Compare the candidate state against `game_winsock_iat_slots.csv` and `game_iat_edges.csv`.
5. Write one concise durable report under `reports\` that answers whether the mapped image currently unblocks concrete Game Winsock IAT slot validation.
6. Stop after that one result.

## Acceptance gate

The report must include candidate path, SHA-256, size, PE validity, image base, size of image, section/range summary, Game Winsock IAT-slot status, and the smallest next action for the main decoder path.

## Escalation condition

Create `control\request_codex.flag` and a complete `handoff\CODEX_REQUEST.md` only if the existing mapped image artifacts are missing, contradictory, or insufficient in a way that blocks Pass665/Pass666 from proving concrete Game Winsock IAT slot VAs.

## Prohibited

- no invalid-page mapping;
- no value seeding;
- no forced RIP/RSP/flags/branches;
- no guest-state mutation;
- no changes to baseline, production, `AION_LOCAL_WORKER_V22`, or `AION_LOCAL_WORKER_V22_2`;
- no broad unpacking/H2 provenance continuation unless it supplies a concrete missing runtime image, page, state, call edge, or initializer needed by the main path.
