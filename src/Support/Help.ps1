function helpSupport {
    $helpText = @"

=======================================
           GARUDA HELP MENU
=======================================

[ COMMAND USAGE EXAMPLES ]

1. Display this help menu:
   .\src\index.ps1 -help

2. Perform Discovery (without port scanning):
   .\src\index.ps1 -targets "10.0.0.0/24" -discover
   .\src\index.ps1 -targets "example.com" -discover
   .\src\index.ps1 -targets "example.com", "8.8.8.8" -discover

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
