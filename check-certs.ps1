$envPythonPath = Join-Path $PSScriptRoot ".venv" "Scripts" "python"
$scriptPath = Join-Path $PSScriptRoot "check-certificates.py"

# SET envPythonPath=%~dp0.venv\Scripts\python
# SET scriptPath=%~dp0check-certificates.py

# Start-Process -FilePath $envPythonPath -ArgumentList $scriptPath -NoNewWindow -Wait
& $envPythonPath $scriptPath

# "%envPythonPath%" "%scriptPath%"
