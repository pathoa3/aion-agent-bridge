param()
$ErrorActionPreference = "Stop"
$repo = "C:\AionTools\aion-agent-bridge"
Set-Location $repo
python (Join-Path $repo "tools\pass665_active_recv_hook\pass665_runner.py")
exit $LASTEXITCODE
