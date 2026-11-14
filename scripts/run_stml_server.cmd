@echo off
REM STML server (background) — reads tokens from the ACL-protected tokens.json.
setlocal
set "DATA=%ProgramData%\AIDefender\stml"
if not exist "%DATA%" mkdir "%DATA%"

set "PY=C:\Users\lomel\AppData\Local\Programs\Python\Python312\python.exe"
if exist "%DATA%\STML-policy.pub" set "STML_POLICY_PUBKEY_FILE=%DATA%\STML-policy.pub"
"%PY%" -m stml.server run ^
  --host 127.0.0.1 ^
  --port 8080 ^
  --db "%DATA%\server.sqlite3" ^
  --trust-dir "%DATA%\trust" ^
  --tokens-file "%DATA%\tokens.json" >> "%DATA%\server.run.log" 2>&1
