<#
.SYNOPSIS
    Tests, builds and collects the release files in dist\:
    KeePassFido2.dll (the plugin), kp.exe, kp-run, optionally the setup program, and SHA256SUMS.

.PARAMETER Tag
    When releasing from a git tag, the tag must be v<version>.

.PARAMETER Installer
    Also build keepass-fido2-<version>-setup.exe with Inno Setup 6.

.PARAMETER InnoSetupCompiler
    Path to ISCC.exe; defaults to the standard Inno Setup 6 install location.
#>
param(
    [string]$Tag,
    [switch]$Installer,
    [string]$InnoSetupCompiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist'

[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props')
$version = ($props.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
if (-not $version) { throw 'No <Version> in Directory.Build.props.' }

$versionTxt = Get-Content (Join-Path $root 'version.txt') -Raw
if ($versionTxt -notmatch "KeePass FIDO2:$([regex]::Escape($version))\b") {
    throw "version.txt does not announce $version; KeePass's update check would report the wrong version."
}
if ($Tag -and $Tag -ne "v$version") { throw "Tag $Tag does not match version $version." }

dotnet test (Join-Path $root 'tests\KeePassFido2.Tests') -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }

if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item (Join-Path $root 'src\KeePassFido2\bin\Release\net48\KeePassFido2.dll') $dist
Copy-Item (Join-Path $root 'src\Kp\bin\Release\net48\kp.exe'), (Join-Path $root 'src\Kp\bin\Release\net48\kp-run') $dist

if ($Installer) {
    if (-not (Test-Path $InnoSetupCompiler)) { throw "Inno Setup compiler not found at $InnoSetupCompiler. Install Inno Setup 6 or pass -InnoSetupCompiler." }
    & $InnoSetupCompiler /Q "/DAppVersion=$version" "/DDistDir=$dist" "/DRepoDir=$root" (Join-Path $root 'installer\keepass-fido2.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Building the installer failed.' }
}

# sha256sum format, so `sha256sum -c SHA256SUMS` works as well as comparing by hand.
$sums = Get-ChildItem $dist -File | Sort-Object Name | ForEach-Object {
    "$((Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
}
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS'), ($sums -join "`n") + "`n")

Write-Host "Release files for $version in $dist"
$sums | ForEach-Object { Write-Host "  $_" }
