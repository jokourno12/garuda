. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Scanner.ps1')))"

function quickScanCommand {
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
