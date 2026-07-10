@echo off
setlocal

REM Run this from the root of a local clone of pathoa3/aion-agent-bridge.
REM Example:
REM   cd C:\AionTools\aion-agent-bridge
REM   scripts\push_bridge_bootstrap.bat

git status
git add .
git commit -m "Initialize agent bridge"
git push
