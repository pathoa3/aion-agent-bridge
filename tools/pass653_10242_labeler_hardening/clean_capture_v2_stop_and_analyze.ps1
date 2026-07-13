# Stop capture manually first, then run this to analyze the current capture with dynamic world-port detection enabled.
$ErrorActionPreference = "Stop"
$repo = "C:\AionTools\aion-agent-bridge"
Push-Location $repo
try {
  powershell -ExecutionPolicy Bypass -File tools\pass653_10242_labeler_hardening\run_pass653_hardening.ps1
}
finally { Pop-Location }
