#Commands
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'DiscoverCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'QuickScanCommand.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Commands', 'FullScanCommand.ps1'))"

#Support
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Support', 'Banner.ps1'))"

#Runtime
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Runtime', 'Windows.ps1'))"

function showBanner {
    supportBanner
}

function helpEngine {
    $helpText = @"

=======================================
           GARUDA HELP MENU
=======================================

[ INSTALLATION & PREPARATION ]
To use this tool, please clone the repository and navigate to its directory:
  git clone https://github.com/jokourno12/garuda
  cd garuda

[ COMMAND USAGE EXAMPLES ]

1. Display this help menu:
   .\src\index.ps1 -help

2. Perform Discovery (without port scanning):
   .\src\index.ps1 -targets "example.com" -discover
   .\src\index.ps1 -targets "example.com", "10.0.0.1" -discover

3. Perform Quick Scan (using default ports):
   .\src\index.ps1 -targets "example.com" -quickScan

4. Perform Full Scan (Ports 1 - 65535):
   .\src\index.ps1 -targets "example.com" -fullScan

5. Perform Scan with Custom Port Range (e.g., ports 100 to 1000):
   .\src\index.ps1 -targets "example.com" -fullScan -pMin 100 -pMax 1000

6. Perform Scan with Specific Ports:
   .\src\index.ps1 -targets "example.com" -fullScan -ports "80", "443", "8080"

7. Perform Combined Scan (Custom Range and Specific Ports):
   .\src\index.ps1 -targets "example.com" -fullScan -pMin 1000 -pMax 2000 -ports "80", "443"

=======================================
"@
    
    Write-Host $helpText @Net
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