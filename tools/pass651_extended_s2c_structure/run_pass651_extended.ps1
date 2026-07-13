$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass651_extended_s2c_structure\stage_a_freshness.py"
  python "tools\pass651_extended_s2c_structure\stage_b_stream_reassembly.py"
  python "tools\pass651_extended_s2c_structure\stage_c_framing_hypotheses.py"
  python "tools\pass651_extended_s2c_structure\stage_d_sequence_crib_search.py"
  python "tools\pass651_extended_s2c_structure\stage_e_10242_sidechannel_model.py"
  python "tools\pass651_extended_s2c_structure\stage_f_next_capture_design.py"
  python "tools\pass651_extended_s2c_structure\stage_g_decision.py"
}
finally {
  Pop-Location
}
