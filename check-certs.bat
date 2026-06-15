@REM $envPythonPath = Join-Path $PSScriptRoot ".venv" "Scripts" "python"
@REM $scriptPath = Join-Path $PSScriptRoot "check-certificates.py"

SET envPythonPath=%~dp0.venv\Scripts\python
SET scriptPath=%~dp0check-certificates.py

@REM # Start-Process -FilePath $envPythonPath -ArgumentList $scriptPath -NoNewWindow -Wait
@REM & $envPythonPath $scriptPath

"%envPythonPath%" "%scriptPath%"
