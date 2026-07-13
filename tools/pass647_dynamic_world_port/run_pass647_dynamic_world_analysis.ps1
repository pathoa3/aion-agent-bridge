$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = "python"
Push-Location $repo
try {
  & $python "tools\pass647_dynamic_world_port\inventory_broad_capture.py"
  & $python "tools\pass647_dynamic_world_port\detect_world_flow.py"
  & $python "tools\pass647_dynamic_world_port\correlate_markers_dynamic_flows.py"
  & $python "tools\pass647_dynamic_world_port\scan_literal_text_dynamic_flows.py"
  & $python "tools\pass647_dynamic_world_port\prepare_7780_oracle_readiness.py"
  & $python "tools\pass647_dynamic_world_port\build_pass647_report.py"
}
finally {
  Pop-Location
}
