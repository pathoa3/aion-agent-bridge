$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = "python"
Push-Location $repo
try {
  & $python "tools\pass648_dynamic_world_s2c_oracle\s2c_oracle_attempt_7780.py"
  & $python "tools\pass648_dynamic_world_s2c_oracle\validate_pass648_candidates.py"
}
finally {
  Pop-Location
}
