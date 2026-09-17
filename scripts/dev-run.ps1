<#
.SYNOPSIS
    Builds the plugin, installs it into the development KeePass from dev-setup.ps1 and starts
    that KeePass with the test database.

.DESCRIPTION
    The development KeePass uses its own unlock store (.dev\unlock.xml), so enrollments made
    while testing never mix with those of your installed KeePass.
#>
param(
    [string]$Database,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    # Install only; leave starting KeePass to you or to kp.exe.
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dev = Join-Path $root '.dev'
$keePassExe = Join-Path $dev 'KeePass\KeePass.exe'
if (-not $Database) { $Database = Join-Path $dev 'test.kdbx' }

if (-not (Test-Path $keePassExe)) { throw 'Run scripts\dev-setup.ps1 first.' }

$devKeePass = Get-Process KeePass -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $keePassExe }
if ($devKeePass) { throw 'The development KeePass is still running; close it first so the plugin can be replaced.' }

foreach ($project in 'src\KeePassFido2\KeePassFido2.csproj', 'src\Kp\Kp.csproj') {
    dotnet build (Join-Path $root $project) -c $Configuration --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Build of $project failed." }
}

$plugins = Join-Path $dev 'KeePass\Plugins'
New-Item -ItemType Directory -Force $plugins | Out-Null
Copy-Item -Force (Join-Path $root "src\KeePassFido2\bin\$Configuration\net48\KeePassFido2.dll") $plugins

$bin = Join-Path $dev 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
Copy-Item -Force (Join-Path $root "src\Kp\bin\$Configuration\net48\kp.exe"), (Join-Path $root "src\Kp\bin\$Configuration\net48\kp-run") $bin
Write-Host "kp.exe and kp-run are in $bin"

$env:KEEPASS_FIDO2_STORE = Join-Path $dev "unlock.xml"
if ($NoStart) {
    Write-Host "Installed. Set KEEPASS_FIDO2_STORE=$env:KEEPASS_FIDO2_STORE before starting the development KeePass."
    return
}
Start-Process -FilePath $keePassExe -ArgumentList "`"$Database`""
Write-Host "Started development KeePass with $Database (store: $env:KEEPASS_FIDO2_STORE)"
