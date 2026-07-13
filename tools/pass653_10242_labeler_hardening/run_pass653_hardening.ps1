$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
function Run-Stage([string]$Path) {
  python $Path
  if ($LASTEXITCODE -ne 0) { throw "Stage failed ($LASTEXITCODE): $Path" }
}
try {
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_a_input_audit.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_b_false_positive_baseline.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_c_event_labeler_v2.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_d_unsupervised_detector.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_e_c2s22_cadence_model.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_f_10242_s2c_batch_clustering.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_g_cross_flow_timing.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_h_clean_capture_v2_kit.py"
  Run-Stage "tools\pass653_10242_labeler_hardening\stage_i_final_decision.py"
}
finally { Pop-Location }
