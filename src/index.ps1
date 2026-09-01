[CmdletBinding()]
param(
	# Mandatory Parameter
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

. "$([System.IO.Path]::Combine($PSScriptRoot, 'Runtime', 'Windows.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Engine.ps1'))"

showBanner

if ($help) {
	helpEngine
	return
}

if (-not $targets) {
	Write-Host "Error: You must enter the target (IP or Domain)." @Pen
	return
}

if ($quickScan) {
	if ($PSBoundParameters.ContainsKey('pMin') -or $PSBoundParameters.ContainsKey('pMax') -or $PSBoundParameters.ContainsKey('ports')) {
		Write-Host "Error: Parameter port (-pMin, -pMax, -ports) not supported in mode -quickScan." @pen
		Write-Host "Please use -fullScan to perform a scan with a custom port." @Cha
		return
	}
}

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
if ($discover) {
    discoverEngine -targets $targets
    return
}

if ($quickScan) {
    quickScanEngine `
        -targets $targets `
        -quickScan:$true
    return
}

if ($fullScan) {
    fullScanEngine `
        -targets $targets `
        -quickScan:$false `
        -pMin $pMin `
        -pMax $pMax `
        -ports $ports
    return
}

