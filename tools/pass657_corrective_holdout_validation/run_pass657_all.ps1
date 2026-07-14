$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass657_corrective_holdout_validation\pass657_runner.py"
  if ($LASTEXITCODE -ne 0) { throw "Pass657 runner failed with exit code $LASTEXITCODE" }
}
finally { Pop-Location }
