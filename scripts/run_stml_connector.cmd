@echo off
REM STML Agent Connector sidecar (Phase A, read-only).
REM Edit paths/tokens if your deployment differs.
setlocal
set "ROOT=%~dp0.."
set "AIDF_DATA=%ProgramData%\AIDefender"
set "STML_DATA=%AIDF_DATA%\stml"
set "STML_SERVER_URL=%STML_SERVER_URL%"
if "%STML_SERVER_URL%"=="" set "STML_SERVER_URL=http://127.0.0.1:8080"
set "STML_TENANT=%STML_TENANT%"
if "%STML_TENANT%"=="" set "STML_TENANT=default"
set "STML_ENROL_TOKEN=%STML_ENROL_TOKEN%"
set "AIDF_ADDRESS=\\.\pipe\aidf"
set "AIDF_AUTHKEY_FILE=%AIDF_DATA%\authkey.hex"
set "AIDF_OPERATOR_TOKEN_FILE=%AIDF_DATA%\operator.token"
if not exist "%STML_DATA%" mkdir "%STML_DATA%"

set "STML_PY=%STML_PY%"
REM SYSTEM has no per-user python on PATH: prefer absolute path, then STML_PY, then PATH.
if not exist "%ProgramData%\AIDefender\stml" mkdir "%ProgramData%\AIDefender\stml"
if "%STML_PY%"=="" set "STML_PY=C:\Users\lomel\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%STML_PY%" set "STML_PY=python"

"%STML_PY%" -m stml.connector run ^
  --tenant "%STML_TENANT%" ^
  --data-root "%AIDF_DATA%" ^
  --spool "%STML_DATA%\spool.sqlite3" ^
  --state "%STML_DATA%\state.json" ^
  --server-url "%STML_SERVER_URL%" ^
  --enrol-token "%STML_ENROL_TOKEN%" ^
  --authkey-file "%AIDF_AUTHKEY_FILE%" ^
  --token-file "%AIDF_OPERATOR_TOKEN_FILE%" ^
  --console ^
  --rpc-lock "%STML_DATA%\rpc.lock"
