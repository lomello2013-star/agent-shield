param(
    [string]$Root = "C:\ProgramData\AIDefender\stml"
)
$ErrorActionPreference = "Stop"
$env:STML_POLICY_PUBKEY_FILE = Join-Path $Root "STML-policy.pub"
$python = "C:\Users\lomel\AppData\Local\Programs\Python\Python312\python.exe"
& $python -m stml.server run `
    --host 127.0.0.1 `
    --port 8080 `
    --db (Join-Path $Root "server.sqlite3") `
    --trust-dir (Join-Path $Root "trust") `
    --tokens-file (Join-Path $Root "tokens.json") *>> (Join-Path $Root "server.run.log")
