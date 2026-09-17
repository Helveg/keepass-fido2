<#
.SYNOPSIS
    Types text into the focused field of an Android device, pressing Tab between the arguments.

.DESCRIPTION
    `adb shell input text` hands its text to the device's shell, which would split or interpret
    spaces, quotes and other characters; this script quotes each value for that shell. Values
    are never printed. Typically run through kp, with the values in environment variables:

        kp run --context tablet --slot WIFI_SSID --slot WIFI_PASSWORD --
            pwsh -NoProfile -c 'tools\adb-type.ps1 $env:WIFI_SSID $env:WIFI_PASSWORD -Enter'

    `input text` types printable ASCII only, and turns the two characters "%s" into a space.

.PARAMETER Values
    The texts to type, in order.

.PARAMETER Serial
    Device serial when more than one device is connected (see `adb devices`).

.PARAMETER Enter
    Press Enter after the last value, e.g. to submit a form.

.PARAMETER NoTab
    Do not press Tab between values.
#>
param(
    [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)]
    [AllowEmptyString()]
    [string[]]$Values,
    [string]$Serial,
    [switch]$Enter,
    [switch]$NoTab
)

$ErrorActionPreference = 'Stop'

$device = @()
if ($Serial) { $device = @('-s', $Serial) }

function Invoke-Adb {
    & adb @device @args
    if ($LASTEXITCODE -ne 0) { throw "adb failed (exit $LASTEXITCODE)." }
}

for ($i = 0; $i -lt $Values.Count; $i++) {
    $value = $Values[$i]
    $position = "value $($i + 1) of $($Values.Count)"

    if ($value -match '[^\x20-\x7E]') {
        Write-Warning "Skipping ${position}: adb can only type printable ASCII."
        continue
    }

    Write-Host "Typing $position"
    $escaped = "'" + $value.Replace("'", "'\''").Replace(' ', '%s') + "'"
    Invoke-Adb shell "input text $escaped"

    if ($i -lt $Values.Count - 1 -and -not $NoTab) { Invoke-Adb shell 'input keyevent 61' }
}

if ($Enter) { Invoke-Adb shell 'input keyevent 66' }
