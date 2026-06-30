param(
    [switch]$Help,
    [switch]$Discover,
    [switch]$FullScan
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

if ($FullScan) {
	fullScan2
}