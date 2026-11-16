function Get-XposedOrNot {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $encodedEmail = [System.Uri]::EscapeDataString($Address)
    $uri = "https://api.xposedornot.com/v1/check-email/$encodedEmail"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop

        $breaches = @()
        if ($response.breaches) {
            $breaches = @($response.breaches[0])
        }

        return [PSCustomObject]@{
            Source   = 'XposedOrNot'
            Status   = if ($breaches.Count -gt 0) { 'Exposed' } else { 'Clean' }
            Count    = $breaches.Count
            Findings = $breaches
            Error    = $null
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 404) {
            return [PSCustomObject]@{
                Source   = 'XposedOrNot'
                Status   = 'Clean'
                Count    = 0
                Findings = @()
                Error    = $null
            }
        }

        return [PSCustomObject]@{
            Source   = 'XposedOrNot'
            Status   = 'Error'
            Count    = 0
            Findings = @()
            Error    = $_.Exception.Message
        }
    }
}

function email {
    param (
        [Parameter(Mandatory = $true)]
        [string]$target
    )

    Write-Host "[*] Querying XposedOrNot..." @Cha
    $result = Get-XposedOrNot -Address $target

    if ($result.Error) {
        Write-Host "    Status  : Error ($($result.Error))" @Pen
        return
    }

    if ($result.Status -eq 'Exposed') {
        Write-Host "    Status  : Exposed ($($result.Count) breach(es) found)" @Pen
        Write-Host "    Sources : $($result.Findings -join ', ')" @Pen
    }
    else {
        Write-Host "    Status  : Clean (0 breaches found)" @Cha
    }
}