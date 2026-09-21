. "$([System.IO.Path]::Combine($PSScriptRoot, 'Runtime', 'Threads.ps1'))"

. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'DiscoverCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'QuickScanCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'FullScanCommand.ps1'))"

. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Banner.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Help.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Dto', 'HostResult.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Dto', 'HostResultTable.ps1'))"

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
            [Parameter(Mandatory = $true)]
            [string[]]$targets
    )

    quickScanCommand -targets $targets
}

function fullScanEngine {
    [CmdletBinding()]
    param(
        [string[]]$targets,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    fullScanCommand -targets $targets -pMin $pMin -pMax $pMax -ports $ports
}