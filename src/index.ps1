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

. "$([System.IO.Path]::Combine($PSScriptRoot, 'Runtime', 'Themes.ps1'))"
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
pMin      : $pMin
pMax      : $pMax
quickScan : $($quickScan.IsPresent)
Targets   : $($targets -join ', ')
Ports     : $($ports -join ', ')
-----------------------------
"@

if ($discover) {
    discoverEngine -targets $targets
    return
}

if ($quickScan) {
    quickScanEngine -targets $targets
    return
}

if ($fullScan) {
    fullScanEngine -targets $targets -pMin $pMin -pMax $pMax -ports $ports
    return
}

Write-Host "Error: No scan mode specified. Use -discover, -quickScan, or -fullScan." @Pen
Write-Host "Run 'garuda -help' for usage information." @Cha