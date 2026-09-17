<#
.SYNOPSIS
    Installs KeePass FIDO2 from an extracted release: the plugin into KeePass's Plugins folder,
    and kp.exe / kp-run into %LOCALAPPDATA%\Programs\keepass-fido2\bin on your PATH.

.DESCRIPTION
    Run it from the extracted folder:
        powershell -ExecutionPolicy Bypass -File .\install.ps1
    Copying into Program Files asks for administrator rights for that one step.

.PARAMETER KeePassDir
    Folder containing KeePass.exe. Defaults to the installed KeePass 2.

.PARAMETER SkipPlugin
    Only install kp.exe and kp-run.

.PARAMETER SkipKp
    Only install the plugin.
#>
param(
    [string]$KeePassDir,
    [switch]$SkipPlugin,
    [switch]$SkipKp
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

# Files extracted from a downloaded zip carry the "downloaded from the internet" mark, which
# keeps .NET from loading the plugin.
Get-ChildItem -Path $here -Recurse -File | Unblock-File

function Find-KeePassDir {
    $key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1'
    foreach ($hive in 'LocalMachine', 'CurrentUser') {
        foreach ($view in 'Registry64', 'Registry32') {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            $sub = $base.OpenSubKey($key)
            if ($sub) {
                $location = $sub.GetValue('InstallLocation')
                if ($location -and (Test-Path (Join-Path $location 'KeePass.exe'))) { return $location.TrimEnd('\') }
            }
        }
    }
    $default = Join-Path $env:ProgramFiles 'KeePass Password Safe 2'
    if (Test-Path (Join-Path $default 'KeePass.exe')) { return $default }
    return $null
}

if (-not $SkipPlugin) {
    if (-not $KeePassDir) { $KeePassDir = Find-KeePassDir }
    if (-not $KeePassDir -or -not (Test-Path (Join-Path $KeePassDir 'KeePass.exe'))) {
        throw 'KeePass 2 was not found. Pass -KeePassDir "C:\path\to\KeePass".'
    }
    $keePassExe = (Resolve-Path (Join-Path $KeePassDir 'KeePass.exe')).Path
    if (Get-Process KeePass -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $keePassExe }) {
        throw 'Close KeePass first, then run the installer again.'
    }

    $source = Join-Path $here 'plugin\KeePassFido2.dll'
    $plugins = Join-Path $KeePassDir 'Plugins'
    $target = Join-Path $plugins 'KeePassFido2.dll'
    try {
        New-Item -ItemType Directory -Force $plugins | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force
    }
    catch [System.UnauthorizedAccessException], [System.IO.IOException] {
        Write-Host 'Copying the plugin needs administrator rights; confirm the Windows prompt.'
        $command = "New-Item -ItemType Directory -Force '$plugins' | Out-Null; Copy-Item -LiteralPath '$source' -Destination '$target' -Force"
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command', $command
    }

    if (-not (Test-Path $target) -or (Get-FileHash $target).Hash -ne (Get-FileHash $source).Hash) {
        throw "The plugin was not copied to $target."
    }
    Write-Host "Plugin installed: $target"
}

if (-not $SkipKp) {
    $bin = Join-Path $env:LOCALAPPDATA 'Programs\keepass-fido2\bin'
    New-Item -ItemType Directory -Force $bin | Out-Null
    Copy-Item -Force (Join-Path $here 'kp\kp.exe'), (Join-Path $here 'kp\kp-run') $bin

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($userPath -split ';' | Where-Object { $_ })
    if ($entries -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', (($entries + $bin) -join ';'), 'User')
        Write-Host "Added $bin to your PATH; open a new terminal to use kp."
    }
    Write-Host "kp installed: $bin\kp.exe"
    $wslBin = '/mnt/' + $bin.Substring(0, 1).ToLowerInvariant() + $bin.Substring(2).Replace('\', '/')
    Write-Host "In WSL, kp-run is reachable through Windows' PATH, or add: export PATH=`"`$PATH:$wslBin`""
}

Write-Host ''
Write-Host 'Next: start KeePass, open a database and use Tools > KeePass FIDO2 > Manage unlock methods.'
