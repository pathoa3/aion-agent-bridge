$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
function Run-Stage([string]$Path) {
  python $Path
  if ($LASTEXITCODE -ne 0) { throw "Stage failed ($LASTEXITCODE): $Path" }
}
try {
  Run-Stage "tools\pass652_10242_event_model\stage_a_isolate_windows.py"
  Run-Stage "tools\pass652_10242_event_model\stage_b_c2s22_field_model.py"
  Run-Stage "tools\pass652_10242_event_model\stage_c_s2c_batch_model.py"
  Run-Stage "tools\pass652_10242_event_model\stage_d_request_response_model.py"
  Run-Stage "tools\pass652_10242_event_model\stage_e_event_fingerprint.py"
  Run-Stage "tools\pass652_10242_event_model\stage_f_text_extraction_feasibility.py"
  Run-Stage "tools\pass652_10242_event_model\stage_g_extractor_design.py"
  Run-Stage "tools\pass652_10242_event_model\prototype_10242_event_labeler.py"
  Run-Stage "tools\pass652_10242_event_model\stage_i_decision.py"
}
finally {
  Pop-Location
}
