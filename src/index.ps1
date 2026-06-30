param(
    [switch]$Help,
    [switch]$Discover,
    [switch]$FullScan
)

# Memuat isi Engine.ps1 ke sesi saat ini
. "$PSScriptRoot\Engine.ps1"

$banner =
"                      
=======================================
  ╔═╗╔═╗╦═╗╦ ╦╔╦╗╔═╗  ╔═╗╔═╗╔╗╔╔═╗╔═╗
  ║ ╦╠═╣╠╦╝║ ║ ║║╠═╣  ╚═╗║╣ ║║║╚═╗║╣ 
  ╚═╝╩ ╩╩╚═╚═╝═╩╝╩ ╩  ╚═╝╚═╝╝╚╝╚═╝╚═╝
                  v1.0
              S2025110106
=======================================
     [ SECURITY OBSERVATION TOOL ]
               TANGERANG
              2026 - 2027
=======================================                                               
"

Write-Host $banner

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