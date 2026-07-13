$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = "python"
Push-Location $repo
try {
  & $python "tools\pass646_10242_structured_model\build_pass646_10242_model.py"
}
finally {
  Pop-Location
}
