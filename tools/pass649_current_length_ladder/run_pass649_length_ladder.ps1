$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass649_current_length_ladder\run_pass649_length_ladder.py"
}
finally {
  Pop-Location
}
