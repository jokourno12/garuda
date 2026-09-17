. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Scanner', 'Scanner.ps1')))"

function quickScanCommand {
[CmdletBinding()]
param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    scanner -targets $targets -quickScan
}
