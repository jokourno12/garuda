#Commands
. $PSScriptRoot\Commands\fullScan.ps1

#Support
. $PSScriptRoot\Support\Banner.ps1

function showBanner {
    supportBanner
}

function helpEngine {
    Write-Host "Hello World From Help"
}

function discoverEngine {
    Write-Host "Hello World From Discover"
}

function fullScan2 {
    fullScan1
}