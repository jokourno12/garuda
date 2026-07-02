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

# Memanggil function yang ada di Engine.ps1
if ($help) {
    	helpEngine
}

if ($discover) {
	discoverEngine
}

if ($quickScan) {
	quickScanEngine
}

