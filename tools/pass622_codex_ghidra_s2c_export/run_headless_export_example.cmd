@echo off
setlocal
REM Pass622 targeted Ghidra export example. Edit GHIDRA_HOME, PROJECT_DIR, and PROJECT_NAME.
set GHIDRA_HOME=C:\ghidra
set PROJECT_DIR=C:\Path\To\GhidraProject
set PROJECT_NAME=EuroAionGameDll
set PROGRAM_NAME=game.dll
set SCRIPT_DIR=C:\AionTools\aion-agent-bridge\tools\pass622_codex_ghidra_s2c_export
set OUT_DIR=C:\AionTools\aion_decoder_agent\outbox\pass622_ghidra_s2c_receive_exports

"%GHIDRA_HOME%\support\analyzeHeadless.bat" "%PROJECT_DIR%" "%PROJECT_NAME%" -process "%PROGRAM_NAME%" -noanalysis -scriptPath "%SCRIPT_DIR%" -postScript ghidra_export_s2c_receive_path.py "%OUT_DIR%"

python "%SCRIPT_DIR%\postprocess_s2c_exports.py" --export-dir "%OUT_DIR%" --repo-root C:\AionTools\aion-agent-bridge
endlocal
