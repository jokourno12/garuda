. $PSScriptRoot\..\Modules\scanner.ps1

function customScanCommand {
[CmdletBinding()]
param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    scanner `
        -targets $targets `
        -quickScan:$quickScan `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}
