[CmdletBinding()]
param(
	# Mandatory Parameter
	[Parameter(Mandatory = $true)]
	[string[]]$targets,
	# Operation Mode
	[switch]$help,
	[switch]$discover,
	[switch]$quickScan,
	[switch]$fullScan,
	# Port Configuration
	[int]$pMin = 1,
	[int]$pMax = 65535,
	[string[]]$ports
)

# Memuat isi Engine.ps1 ke sesi saat ini
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Engine.ps1'))"

showBanner

# DEBUGGING
Write-Information @"
   Debugging information
-----------------------------
pMin: $pMin
pMax: $pMax
quickScan: $($quickScan.IsPresent)
Targets: $targets
Ports: $ports
-----------------------------
"@

# Memanggil function yang ada di Engine.ps1
if ($help) {
    	helpEngine
	return
}

if ($discover) {
	discoverEngine
	return
}

if ($quickScan) {
    quickScanEngine `
        -targets $targets `
        -quickScan:$true `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}

if ($fullScan) {
    # FULL SCAN DEFAULT
    fullScanEngine `
        -targets $targets `
        -quickScan:$false `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}

