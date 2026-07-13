$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
function Run-Stage([string]$Path) {
  python $Path
  if ($LASTEXITCODE -ne 0) { throw "Stage failed ($LASTEXITCODE): $Path" }
}
try {
  Run-Stage "tools\pass654b_offline_capture_validation\stage_a_input_and_oracle_merge.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_b_dynamic_flow_inventory.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_c_local_say_control.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_d_stream_reassembly.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_e_known_text_location.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_f_10242_format_analysis.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_g_world_flow_format_analysis.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_h_whisper_group_comparison.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_i_cross_validation.py"
  Run-Stage "tools\pass654b_offline_capture_validation\stage_j_final_decision.py"
}
finally { Pop-Location }
