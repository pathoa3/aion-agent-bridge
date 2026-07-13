$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
  $python = "python"
}

Push-Location $repo
try {
  & $python "tools\pass638_after_capture\validate_known_plaintext_log.py"
  & $python "tools\pass638_after_capture\report_dynamic_flow_context.py"
  & $python "tools\pass645_10242_oracle_analysis\inventory_10242_capture.py"
  & $python "tools\pass645_10242_oracle_analysis\scan_10242_known_text.py"
  & $python "tools\pass645_10242_oracle_analysis\correlate_10242_markers.py"
  & $python "tools\pass645_10242_oracle_analysis\build_10242_decision_report.py"
  powershell -ExecutionPolicy Bypass -File tools\agent_helpers\agent_safe_checkpoint.ps1 -Message "Analyze fresh S2C oracle capture on 10242"
}
finally {
  Pop-Location
}
