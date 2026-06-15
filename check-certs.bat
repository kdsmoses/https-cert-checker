@echo off
SET envPythonPath=%~dp0.venv\Scripts\python
SET scriptPath=%~dp0check-certificates.py

"%envPythonPath%" "%scriptPath%"
