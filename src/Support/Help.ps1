function helpSupport {
    $helpText = @"

=======================================
           GARUDA HELP MENU
=======================================

[ COMMAND USAGE EXAMPLES ]

1. Display this help menu:
   garuda -help

2. Perform Discovery (without port scanning):
   garuda -targets "10.0.0.0/24" -discover
   garuda -targets "example.com" -discover
   garuda -targets "example.com", "8.8.8.8" -discover

3. Perform Quick Scan (using default ports):
   garuda -targets "example.com" -quickScan

4. Perform Full Scan (Ports 1 - 65535):
   garuda -targets "example.com" -fullScan

5. Perform Scan with Custom Port Range (e.g., ports 100 to 1000):
   garuda -targets "example.com" -fullScan -pMin 100 -pMax 1000

6. Perform Scan with Specific Ports:
   garuda -targets "example.com" -fullScan -ports "80", "443", "8080"

7. Perform Combined Scan (Custom Range and Specific Ports):
   garuda -targets "example.com" -fullScan -pMin 1000 -pMax 2000 -ports "80", "443"

=======================================
"@
    
    Write-Host $helpText @Net
}
