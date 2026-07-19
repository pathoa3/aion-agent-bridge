# Aion Autonomous Worker Status

Generated: 2026-07-19T09:53:31.0738322+02:00

Repository: pathoa3/aion-agent-bridge
Branch: worker/runtime-status

This status is produced automatically by the isolated Hermes/Gemma worker.
It intentionally excludes raw logs, binaries, checkpoints, captures, configuration
files, credentials, and other large or sensitive artifacts.

## Supervisor heartbeat

{
    "timestamp":  "2026-07-19T09:52:09.7393403+02:00",
    "phase":  "local_cycle",
    "cycle":  27,
    "message":  "",
    "supervisor_pid":  56336,
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
    "last_cycle_exit":  0,
    "consecutive_failure_count":  0,
    "last_failure_signature":  ""
}


## Background supervisor

{
    "timestamp":  "2026-07-19T08:46:30.7567050+02:00",
    "pid":  56336,
    "process_name":  "powershell",
    "worker_root":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND",
    "stdout":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND\\logs\\background-supervisor-20260719_084630.stdout.log",
    "stderr":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND\\logs\\background-supervisor-20260719_084630.stderr.log",
    "visible_window":  false,
    "max_cycles":  0,
    "local_max_turns":  12,
    "codex_max_turns":  90,
    "sleep_seconds":  10,
    "local_provider":  "ollama",
    "local_model":  "gemma4:12b",
    "local_endpoint":  "http://localhost:11434/v1",
    "codex_model":  "gpt-5.6-sol",
    "command_timeout_seconds":  1800
}


## Last completed Hermes cycle

{
    "timestamp":  "2026-07-19T09:51:59.3016458+02:00",
    "mode":  "Local",
    "exit_code":  0,
    "log":  "C:\\AionTools\\AION_HERMES_AUTONOMOUS_WORKER_V1_4_WINDOWS_BACKGROUND\\logs\\local-cycle-20260719_095057.log",
    "hermes":  "C:\\Users\\patho\\AppData\\Local\\hermes\\hermes-agent\\venv\\Scripts\\hermes.exe",
    "hermes_home":  "C:\\Users\\patho\\AppData\\Local\\hermes",
    "project_root":  "C:\\AionTools",
    "provider":  "ollama",
    "model":  "gemma4:12b",
    "endpoint":  "http://localhost:11434/v1",
    "result_state":  "completed",
    "diagnostic_category":  "success",
    "elapsed_seconds":  61.292,
    "failure":  ""
}


## Current accepted project state

# Current Autonomous Worker State

Directive: operator-20260719-pass667-indirect-receive-dispatch-v1
Reconciled: 2026-07-19T08:20:00+02:00

## Main project objective

Recover EuroAion's live receive/decryption boundary sufficiently to decode sequential world/chat traffic and feed plaintext chat into the automatic translation pipeline.

## Accepted evidence

Pass666 authoritative decision: C:\AionTools\aion_decoder_agent\outbox\pass666_recv_boundary\pass666_decision.json.

Accepted:
- mapped Game image validated: C:\AionTools\aion_decoder_agent\outbox\game_until_text_550m_v5_premap_ignoreexit\mapped_game_baseline.bin
- SHA-256: a6417733c712f36253c410462b49de65677b22f0f8618fe288f4d04c25dde04b
- image base: 0x10000000
- image size: 0x1B5D000
- WS2_32 receive-side IAT slot VAs are proven: WSARecvFrom 0x119fd030, WSARecv 0x119fd040, recv 0x119fd108, recvfrom 0x119fd138.

Not accepted:
- Pass666 acceptance remains not_passed.
- No direct instruction xref to WSARecv or recv was proven.
- Import-symbol/DATA references are not executable callsites.
- No active recv/WSARecv hook installer, receive invocation edge, received-buffer handoff, or outer receive transform is proven.

## Rejected historical output

C:\AionTools\reports\pass666_receive_resolution_REJECTED_OVERCLAIM.md is rejected as accepted evidence because it promoted IAT data-slot addresses as candidate executable callsites/thunks. An IAT slot address is a data location and cannot by itself prove a caller or thunk.

## Active supporting task

Run exactly one bounded existing-artifact-only Pass667 indirect receive dispatch pass from state\TASK_QUEUE.md.


## Latest local-worker result

# Local Cycle Result

## Active Task Artifact Check
**Task**: Pass667 Indirect Receive Dispatch
**Action**: Perform exactly one tiny existing-artifact check for the active task.
**Findings**:
- Target IAT slots (0x119fd030, 0x119fd040, 0x119fd108, 0x119fd138) are confirmed as validated evidence items in `EVIDENCE_INDEX.md` and `TASK_QUEUE.md`.
- Search for these specific addresses across the project indicates they appear primarily in report/metadata files (e.g., `.md`, `.csv`) rather than as direct executable offset references or code comments in assembly source unless manually audited in reports like `report-20260719_094840_cycle_23`.
- Current status: Requirement "Code that reads or copies ranges containing [the IAT slots]" is identified but the specific *caller* or *loader logic* providing and utilizing these addresses is not yet isolated as a primary code structure.

**Selected Evidence/Missing Artifact**:
The core finding for this cycle is the confirmation of the physical existence of 0x119fd030, 0x119fd040, 0x119fd108, and 0x119fd138 as the primary targets. However, a **direct executable dereference or copy loop** involving these specific values is still missing from current high-confidence highlights in automated searches of raw code files.

**Next Action**: Analyze surrounding memory (neighboring 0x100 bytes) and related logic to find any hardcoded offset calculations that resolve to these IAT slots.


## Pending Codex request

# Codex Request

Status: no active Codex request.

The stale H2 provenance request is retired. The overclaimed Pass666 report has been rejected as accepted evidence. Local worker target: operator-20260719-pass667-indirect-receive-dispatch-v1.


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

Directive: operator-20260719-pass667-indirect-receive-dispatch-v1

## Completed

- Hermes provider/model routing uses Local provider ollama, model gemma4:12b, endpoint http://localhost:11434/v1.
- Pass665 mapped Game image inventory is complete.
- Pass666 mapped image and Winsock IAT slots are validated.
- The prior pass666_receive_resolution.md output is rejected as overclaimed evidence.

## Active Task: Pass667 Indirect Receive Dispatch

Using existing artifacts only, determine how receive-side Winsock function pointers are invoked when the validated IAT slots have no direct executable xrefs.

Analyze, in order:
1. Exact 8-byte occurrences of current or expected receive-function pointers in mapped images and existing snapshots.
2. Code that reads or copies ranges containing 0x119fd030, 0x119fd040, 0x119fd108, and 0x119fd138.
3. Bulk IAT-copy loops or function-table initialization.
4. Indirect register calls whose dataflow can reach a copied Winsock pointer.
5. Dynamic resolution through LoadLibrary/GetProcAddress or equivalent resolver tables.
6. Receive calls in CrySystem, security modules, or other loaded modules rather than Game.
7. Evidence of runtime-generated thunks or missing executable pages.

## Acceptance gate

Produce exactly one durable report containing: source pointer or table address; code address reading/copying it; candidate indirect callsite when found; disassembly-backed evidence; confidence; whether buffer-handoff tracing is now unblocked; smallest next action.

The Local worker must not claim resolution merely because an import symbol or IAT slot exists.

## Escalation condition

Create control\request_codex.flag and a complete handoff\CODEX_REQUEST.md only if existing artifacts are missing, contradictory, or insufficient to decide whether indirect receive-dispatch candidates exist.

## Prohibited

No production/guest-state mutation, invalid-page mapping, value seeding, forced control flow, binary patching, hooks, injection, live process attachment, H2 null-RAX continuation, or changes to AION_LOCAL_WORKER_V22/AION_LOCAL_WORKER_V22_2.
