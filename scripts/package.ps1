<#
.SYNOPSIS
    Tests, builds and packages a release: dist\keepass-fido2-<version>.zip plus its SHA-256.

.PARAMETER Tag
    When releasing from a git tag, the tag must be v<version>.
#>
param(
    [string]$Tag
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

$name = "keepass-fido2-$version"
$stage = Join-Path $dist $name
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force (Join-Path $stage 'plugin'), (Join-Path $stage 'kp') | Out-Null

Copy-Item (Join-Path $root 'src\KeePassFido2\bin\Release\net48\KeePassFido2.dll') (Join-Path $stage 'plugin')
Copy-Item (Join-Path $root 'src\Kp\bin\Release\net48\kp.exe'), (Join-Path $root 'src\Kp\bin\Release\net48\kp-run') (Join-Path $stage 'kp')
Copy-Item (Join-Path $root 'packaging\install.ps1'), (Join-Path $root 'README.md'), (Join-Path $root 'LICENSE') $stage

$zip = Join-Path $dist "$name.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
Set-Content -Path "$zip.sha256" -Value "$hash  $name.zip" -Encoding ascii -NoNewline

Write-Host "Packaged $zip"
Write-Host "SHA-256 $hash"
