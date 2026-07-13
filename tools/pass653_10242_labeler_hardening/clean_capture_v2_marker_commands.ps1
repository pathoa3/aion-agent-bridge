# Marker commands to paste/send manually in the target workflow; this script only prints them.
$marker64 = "S2C_V2_0064_" + ("X" * 52)
$marker96 = "S2C_V2_0096_" + ("Y" * 84)
Write-Host "Whisper-only markers. Send each 20-30 seconds apart. No group markers in this first pass."
1..5 | ForEach-Object { Write-Host $marker64 }
1..5 | ForEach-Object { Write-Host $marker96 }
