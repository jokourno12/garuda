#Commands
. $PSScriptRoot\Commands\quickScanCommand.ps1
. $PSScriptRoot\Commands\discoverCommand.ps1

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

