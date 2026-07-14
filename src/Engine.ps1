#Commands
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'DiscoverCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'QuickScanCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'FullScanCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'CustomScanCommand.ps1'))"

#Support
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Banner.ps1'))"

function showBanner {
    supportBanner
}

function helpEngine {
    Write-Host "Hello World From Help"
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
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    quickScanCommand `
        -targets $targets `
        -quickScan:$quickScan `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
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

    quickScanCommand `
        -targets $targets `
        -quickScan:$quickScan `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}

function customScanEngine {
	[CmdletBinding()]
	param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    quickScanCommand `
        -targets $targets `
        -quickScan:$quickScan `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}