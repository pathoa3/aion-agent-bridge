$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass656_sequence_correct_body_transform\pass656_runner.py"
  if ($LASTEXITCODE -ne 0) { throw "Pass656 runner failed with exit code $LASTEXITCODE" }
}
finally { Pop-Location }
