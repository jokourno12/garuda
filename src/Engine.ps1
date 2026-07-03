#Commands
. $PSScriptRoot\Commands\DiscoverCommand.ps1
. $PSScriptRoot\Commands\QuickScanCommand.ps1
. $PSScriptRoot\Commands\FullScanCommand.ps1
. $PSScriptRoot\Commands\CustomScanCommand.ps1

#Support
. $PSScriptRoot\Support\Banner.ps1

function showBanner {
    supportBanner
}

function helpEngine {
    Write-Host "Hello World From Help"
}

function discoverEngine {
    	discoverCommand
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