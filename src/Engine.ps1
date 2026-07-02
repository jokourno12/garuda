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
	quickScanCommand
}

