[CmdletBinding()]
param(
	# Mandatory Parameter
	[Parameter(Mandatory = $true)]
	[string[]]$targets,
	# Operation Mode
	[switch]$help,
	[switch]$discover,
	[switch]$quickScan,
	# Port Configuration
	[int]$pMin = 1,
	[int]$pMax = 65535,
	[string[]]$ports
)

# Memuat isi Engine.ps1 ke sesi saat ini
. "$PSScriptRoot\Engine.ps1"

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
}
elseif ($discover) {
    discoverEngine
}
elseif ($quickScan) {
    quickScanEngine `
        -targets $targets `
        -quickScan:$true `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}
else {
    # FULL SCAN DEFAULT
    quickScanEngine `
        -targets $targets `
        -quickScan:$false `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
}