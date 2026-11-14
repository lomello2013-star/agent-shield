#requires -RunAsAdministrator
<#
.SYNOPSIS
    Build the AidfFilter minifilter with the installed WDK + MSVC.
.DESCRIPTION
    Produces out\AidfFilter.sys. Test-signing only; production needs EV + WHQL.
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot "out"),
    [string]$KitsRoot = "C:\Program Files (x86)\Windows Kits\10",
    [string]$KitVersion = "10.0.26100.0"
)

$ErrorActionPreference = "Stop"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install Visual Studio C++ tools" }
$vsPath = & $vswhere -latest -products * -property installationPath
if (-not $vsPath) { throw "Visual Studio not found" }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found" }

$kmInc = Join-Path $KitsRoot "Include\$KitVersion\km"
$kmLib = Join-Path $KitsRoot "Lib\$KitVersion\km\x64"
$shared = Join-Path $KitsRoot "Include\$KitVersion\shared"
$ucrt = Join-Path $KitsRoot "Include\$KitVersion\ucrt"
foreach ($p in @($kmInc, $kmLib, $shared, $ucrt)) {
    if (-not (Test-Path $p)) { throw "WDK path missing: $p (install the WDK)" }
}

# cmd.exe mangles non-ASCII paths, so build in an ASCII directory and copy back.
$buildDir = Join-Path $env:ProgramData "AIDefender\driver-build"
New-Item -ItemType Directory -Force -Path $buildDir, $OutDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot "AidfFilter.c") $buildDir -Force
$obj = Join-Path $buildDir "AidfFilter.obj"
$sys = Join-Path $buildDir "AidfFilter.sys"
$cmdPath = Join-Path $buildDir "build.cmd"

$lines = @(
    "call `"$vcvars`"",
    "cl /nologo /c /GS- /kernel /D_AMD64_ /DAMD64 /DWIN32=100 /D_NTDRIVER_=1 /DUNICODE /D_UNICODE /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 /I`"$kmInc`" /I`"$kmInc\crt`" /I`"$shared`" /I`"$ucrt`" /Fo`"$obj`" `"$buildDir\AidfFilter.c`"",
    "if errorlevel 1 exit /b 1",
    "link /nologo /DRIVER /SUBSYSTEM:NATIVE /MACHINE:X64 /ENTRY:DriverEntry /INCREMENTAL:NO /OUT:`"$sys`" /LIBPATH:`"$kmLib`" `"$obj`" fltmgr.lib ntoskrnl.lib hal.lib wdm.lib BufferOverflowK.lib",
    "exit /b %errorlevel%"
)
Set-Content -Path $cmdPath -Value ($lines -join "`r`n") -Encoding ASCII

& cmd.exe /c $cmdPath
if ($LASTEXITCODE -ne 0) { throw "driver build failed with exit $LASTEXITCODE" }
$final = Join-Path $OutDir "AidfFilter.sys"
Copy-Item $sys $final -Force
Get-Item $final | Select-Object FullName, Length, LastWriteTime
