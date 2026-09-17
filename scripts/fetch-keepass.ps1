<#
.SYNOPSIS
    Downloads the portable KeePass the plugin is built and tested against, into .dev\KeePass.

.DESCRIPTION
    For build machines without KeePass installed. The download is pinned by SHA-256; bump both
    values together when moving to a newer KeePass.
#>
param(
    [string]$Destination = (Join-Path (Split-Path -Parent $PSScriptRoot) '.dev\KeePass')
)

$ErrorActionPreference = 'Stop'
$version = '2.61.1'
$sha256 = '3952354DB9B117E906F7CD4F9F5591065B95186472370DA47F46F3E246FEA864'
$url = "https://downloads.sourceforge.net/project/keepass/KeePass%202.x/$version/KeePass-$version.zip"

if (Test-Path (Join-Path $Destination 'KeePass.exe')) {
    Write-Host "KeePass already present in $Destination"
    return
}

$zip = Join-Path ([IO.Path]::GetTempPath()) "KeePass-$version.zip"
# curl.exe (built into Windows 10+): SourceForge answers Invoke-WebRequest with its HTML download page.
& curl.exe --fail --silent --show-error --location --output $zip $url
if ($LASTEXITCODE -ne 0) { throw "Downloading $url failed." }
$actual = (Get-FileHash -Algorithm SHA256 $zip).Hash
if ($actual -ne $sha256) { throw "KeePass download has SHA-256 $actual, expected $sha256." }

New-Item -ItemType Directory -Force $Destination | Out-Null
Expand-Archive -Path $zip -DestinationPath $Destination -Force
Remove-Item $zip
Write-Host "KeePass $version extracted to $Destination"
