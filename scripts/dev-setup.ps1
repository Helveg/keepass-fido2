<#
.SYNOPSIS
    Creates an isolated KeePass for plugin development in .dev/:
    a copy of the installed KeePass with its own configuration, and a test database.

.DESCRIPTION
    The copy keeps its configuration next to KeePass.exe, does not hand files to an already
    running KeePass (single-instance mode off), and never checks for updates. Your installed
    KeePass, its configuration and your databases are not touched.

    Test database: .dev\test.kdbx, master password "test".
#>
param(
    [string]$KeePassDir = "$env:ProgramW6432\KeePass Password Safe 2",
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# KeePassLib is a .NET Framework assembly; only Windows PowerShell can load it.
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
    exit $LASTEXITCODE
}

$root = Split-Path -Parent $PSScriptRoot
$dev = Join-Path $root '.dev'
$keePass = Join-Path $dev 'KeePass'
$database = Join-Path $dev 'test.kdbx'

if (-not (Test-Path (Join-Path $KeePassDir 'KeePass.exe'))) {
    throw "KeePass not found in '$KeePassDir'. Pass -KeePassDir."
}

if ($Force -and (Test-Path $keePass)) { Remove-Item -Recurse -Force $keePass }
if (-not (Test-Path $keePass)) {
    New-Item -ItemType Directory -Force $keePass | Out-Null
    Copy-Item -Recurse -Force (Join-Path $KeePassDir '*') $keePass -Exclude 'KeePass.config*.xml'
    Write-Host "Copied KeePass to $keePass"
}

@'
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Meta>
    <PreferUserConfiguration>false</PreferUserConfiguration>
  </Meta>
  <Application>
    <Start>
      <CheckForUpdate>false</CheckForUpdate>
      <CheckForUpdateConfigured>true</CheckForUpdateConfigured>
    </Start>
  </Application>
  <Integration>
    <LimitToSingleInstance>false</LimitToSingleInstance>
  </Integration>
</Configuration>
'@ | Set-Content -Encoding UTF8 (Join-Path $keePass 'KeePass.config.xml')

$enforced = Join-Path $keePass 'KeePass.config.enforced.xml'
if (Test-Path $enforced) { Remove-Item $enforced }

$sample = Join-Path $dev 'sample-project'
if ($Force -or -not (Test-Path (Join-Path $sample '.env'))) {
    New-Item -ItemType Directory -Force $sample | Out-Null
    # Fake values for trying `kp import` and `kp run`.
    @'
# Sample project settings (fake values)
PORT=3000
DATABASE_URL="postgres://app:not-a-real-password@localhost:5432/app"
JWT_SECRET=fake-jwt-secret-for-testing
STRIPE_API_KEY=sk_test_fake_0123456789
PUBLIC_BASE_URL=http://localhost:3000
'@ | Set-Content -Encoding UTF8 (Join-Path $sample '.env')
    Write-Host "Created $sample\.env with fake values"
}

if ($Force -and (Test-Path $database)) { Remove-Item $database }
if (-not (Test-Path $database)) {
    [Reflection.Assembly]::LoadFrom((Join-Path $keePass 'KeePass.exe')) | Out-Null
    $key = New-Object KeePassLib.Keys.CompositeKey
    $key.AddUserKey((New-Object KeePassLib.Keys.KcpPassword('test')))
    $db = New-Object KeePassLib.PwDatabase
    $db.New([KeePassLib.Serialization.IOConnectionInfo]::FromPath($database), $key)
    $db.Name = 'keepass-fido2 test database'
    $entry = New-Object KeePassLib.PwEntry($true, $true)
    $entry.Strings.Set('Title', (New-Object KeePassLib.Security.ProtectedString($false, 'Example entry')))
    $entry.Strings.Set('Password', (New-Object KeePassLib.Security.ProtectedString($true, 'it-works')))
    $db.RootGroup.AddEntry($entry, $true)
    $db.Save($null)
    $db.Close()
    Write-Host "Created $database (master password: test)"
}
