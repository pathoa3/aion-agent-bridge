$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $repo
try {
  python "tools\pass650_marker_window_structure\analyze_marker_windows.py"
}
finally {
  Pop-Location
}
