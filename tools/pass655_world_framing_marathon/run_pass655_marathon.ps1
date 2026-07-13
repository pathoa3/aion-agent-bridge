$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass655_world_framing_marathon\pass655_queue.py"
  if ($LASTEXITCODE -ne 0) { throw "Pass655 marathon runner failed with exit code $LASTEXITCODE" }
}
finally { Pop-Location }
