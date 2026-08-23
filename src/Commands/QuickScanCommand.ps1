. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Scanner', 'Scanner.ps1')))"

function quickScanCommand {
[CmdletBinding()]
param(
        [string[]]$targets,
        [switch]$quickScan
    )

    scanner `
        -targets $targets `
        -quickScan:$quickScan
}
