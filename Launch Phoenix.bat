@echo off
set "SCRIPT_DIR=%~dp0"
py "%SCRIPT_DIR%tools\launch_phoenix.py"
if errorlevel 1 pause
