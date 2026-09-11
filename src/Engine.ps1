#Commands
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'DiscoverCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'QuickScanCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'FullScanCommand.ps1'))"

#Support
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Banner.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Help.ps1'))"

#Runtime
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Runtime', 'Windows.ps1'))"

function showBanner {
    supportBanner
}

function helpEngine {
    helpSupport
}

function discoverEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    discoverCommand -targets $targets
}

function quickScanEngine {
	[CmdletBinding()]
	param(
            [string[]]$targets,
            [switch]$quickScan
    )

    quickScanCommand `
        -targets $targets `
        -quickScan:$quickScan
}

function fullScanEngine {
	[CmdletBinding()]
	param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    fullScanCommand `
        -targets $targets `
        -quickScan:$quickScan `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}