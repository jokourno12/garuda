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

if ($help) {
    Get-Help .\portScan.ps1 -Full
    exit
}

Write-Host $banner


# Memanggil function yang ada di Engine.ps1
Show-Hello
Show-Hello