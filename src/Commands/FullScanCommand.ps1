. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Scanner', 'Scanner.ps1')))"

function fullScanCommand {
[CmdletBinding()]
param(
        [string[]]$targets,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    scanner `
        -targets $targets `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}