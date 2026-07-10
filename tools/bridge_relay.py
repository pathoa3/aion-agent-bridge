import argparse, json, os, subprocess, time
from pathlib import Path
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

def load_env(repo_dir: Path):
    if load_dotenv:
        load_dotenv(repo_dir / ".env")
    return {
        "enable_openai": os.getenv("BRIDGE_ENABLE_OPENAI", "false").lower() == "true",
        "model": os.getenv("OPENAI_SUPERVISOR_MODEL", "gpt-5.5"),
        "poll": int(os.getenv("BRIDGE_POLL_SECONDS", "120")),
    }

def read_text(path: Path, default=""):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return default

def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

def init_repo(repo: Path):
    for d in ["state", "inbox", "outbox", "artifacts", "templates"]:
        (repo / d).mkdir(parents=True, exist_ok=True)
    if not (repo / ".gitignore").exists():
        write_text(repo / ".gitignore", "*.pcap\n*.pcapng\n*.dll\n*.bin\n*.exe\n*.zip\n*.7z\n*.rar\n.env\nsecrets*\ncaptures/\nbinaries/\nprivate/\n")
    if not (repo / "inbox" / "README.md").exists():
        write_text(repo / "inbox" / "README.md", "Agents write sanitized reports here. No PCAPs, binaries, keys, or credentials.\n")
    if not (repo / "state" / "current_status.json").exists():
        write_text(repo / "state" / "current_status.json", json.dumps({"current_state":"blocked_need_new_code_evidence"}, indent=2))
    print(f"Initialized safe bridge files in {repo}")

def build_packet(repo: Path):
    packet = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "current_status": read_text(repo / "state" / "current_status.json"),
        "accepted_baseline": read_text(repo / "state" / "accepted_baseline.md"),
        "task_queue": read_text(repo / "state" / "task_queue.json"),
        "antigravity_report": read_text(repo / "inbox" / "antigravity_report.md"),
        "openclaw_report": read_text(repo / "inbox" / "openclaw_report.md"),
        "codex_report": read_text(repo / "inbox" / "codex_report.md"),
    }
    write_text(repo / "outbox" / "supervisor_packet.json", json.dumps(packet, indent=2))
    return packet

def local_decision(packet):
    reports = "\n".join([packet.get("antigravity_report",""), packet.get("openclaw_report",""), packet.get("codex_report","")]).lower()
    if "artifact_obtained: yes" in reports or "useful_candidate" in reports:
        decision = {
            "decision":"run_codex_static_triage",
            "next_worker":"codex",
            "next_action":"Analyze the obtained candidate artifact offline/static only.",
            "decoder_success": False,
            "reason":"Agent report suggests a candidate artifact may exist."
        }
    else:
        decision = {
            "decision":"continue_acquisition",
            "next_worker":"antigravity",
            "next_action":"""Pass603 targeted acquisition only. Do not repeat broad Pass602 source-code searches.

Find concrete downloadable candidate artifacts only:
1. Aion 4.6 / 4.7.5 client archive containing Game.dll or aion.bin.
2. Unpacked / less-protected Game.dll or aion.bin.
3. Forum attachment or mirror that contains actual client binaries.
4. Decompiled/static source with a non-public game-channel packet transform/key schedule.

Reject AionEmu/RageZone/NewCrypt/Crypt public reference crypto, zzsort/version.dll redirector-only code, Cheat Engine scripts, bot offsets, memory hacks, injection/debugging/anti-cheat bypass instructions, and packet injection tools.

Write:
- inbox/antigravity_report.md
- artifacts/pass603_candidates.md
- artifacts/pass603_candidates.csv
- artifacts/pass603_decision.json

If no concrete downloadable artifact is found:
decision = no_artifact_obtained
next = stop_repeating_same_search

If a candidate artifact is found:
decision = candidate_artifact_found
next = manual_download_to_local_new_samples

Do not commit binaries, PCAPs, archives, API keys, or private files to GitHub.""",
            "decoder_success": False,
            "reason":"No concrete new artifact obtained yet."
        }
    return decision

def openai_decision(packet, model):
    from openai import OpenAI
    client = OpenAI()
    prompt = f"""You are the supervisor for a EuroAion 7785 offline decoder project.

Hard rules:
- No live process, debugger, memory dump, injection, anti-cheat bypass, packet injection.
- Do not claim decoder success unless decoded_cleartext.txt and oracle_match exist.
- Public AionEmu/RageZone/Aion4.9/Gamez reference crypto is already exhausted.
- Current blocker is missing EuroAion/comparable code-side transform/key evidence.

Input packet:
{json.dumps(packet, indent=2)[:50000]}

Return strict JSON with:
decision, next_worker, next_action, reason, decoder_success.
"""
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"user","content":prompt}],
        temperature=0,
    )
    text = resp.choices[0].message.content or "{}"
    try:
        return json.loads(text.strip().strip("`").replace("json\n","",1))
    except Exception:
        return {"decision":"supervisor_parse_error","next_worker":"human","next_action":"Review raw supervisor text","reason":text[:4000],"decoder_success":False}

def run_once(repo: Path, env):
    packet = build_packet(repo)
    decision = openai_decision(packet, env["model"]) if env["enable_openai"] else local_decision(packet)
    write_text(repo / "outbox" / "supervisor_decision.json", json.dumps(decision, indent=2))
    if decision.get("next_worker") == "antigravity":
        write_text(repo / "outbox" / "next_task_for_antigravity.md", "# Next task for Antigravity\n\n" + decision.get("next_action","") + "\n")
    elif decision.get("next_worker") == "codex":
        write_text(repo / "outbox" / "next_task_for_codex.md", "# Next task for Codex\n\n" + decision.get("next_action","") + "\n")
    print(json.dumps(decision, indent=2))
    return decision

def git_push(repo: Path):
    subprocess.run(["git","add","."], cwd=repo, check=False)
    subprocess.run(["git","commit","-m","Bridge relay update"], cwd=repo, check=False)
    subprocess.run(["git","push"], cwd=repo, check=False)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", default=os.getenv("BRIDGE_REPO_DIR", "."))
    p.add_argument("--init", action="store_true")
    p.add_argument("--once", action="store_true")
    p.add_argument("--push", action="store_true")
    p.add_argument("--loop", action="store_true")
    args = p.parse_args()
    repo = Path(args.repo).resolve()
    env = load_env(repo)
    if args.init:
        init_repo(repo)
    if args.once:
        run_once(repo, env)
        if args.push:
            git_push(repo)
    if args.loop:
        while True:
            run_once(repo, env)
            if args.push:
                git_push(repo)
            time.sleep(env["poll"])

if __name__ == "__main__":
    main()
