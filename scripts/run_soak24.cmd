@echo off
rem One-shot 24-hour supervised soak, launched by Task Scheduler so it survives the
rem harness session (a process started from the session inherits its job object).
rem Python 3.12.9, health-sampling profile (the one that used to crash), supervisor on.
cd /d "%~dp0.."
set DURATION_S=86400
set AIDF_CHILD_HEALTH=1
set VERBOSE=1
set PYTHONIOENCODING=utf-8
set PYTHONUNBUFFERED=1
"C:\Users\lomel\AppData\Local\Programs\Python\Python312\python.exe" scripts\soak_supervised.py >> artifacts\_stdout\soak24_run.txt 2>&1
