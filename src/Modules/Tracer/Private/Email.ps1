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

function Get-CavalierEmail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $encodedEmail = [System.Uri]::EscapeDataString($Address)
    $uri = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=$encodedEmail"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop

        $stealers = @()
        if ($response.stealers) {
            $stealers = @($response.stealers)
        }

        return [PSCustomObject]@{
            Source   = 'HudsonRock-Cavalier'
            Status   = if ($stealers.Count -gt 0) { 'Compromised' } else { 'Clean' }
            Count    = $stealers.Count
            Findings = $stealers
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
                Source   = 'HudsonRock-Cavalier'
                Status   = 'Clean'
                Count    = 0
                Findings = @()
                Error    = $null
            }
        }

        return [PSCustomObject]@{
            Source   = 'HudsonRock-Cavalier'
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

    Write-Host "[1] Contact info..." @Cha
    Write-Host "    Status  : no data" @Pen

    Write-Host "[2] Network Connection..." @Cha
    Write-Host "    Status  : no data" @Pen

    Write-Host "[3] Hacker Activity (XposedOrNot)..." @Cha
    $result = Get-XposedOrNot -Address $target

    if ($result.Error) {
        Write-Host "    Status  : Error ($($result.Error))" @Pen
    }
    elseif ($result.Status -eq 'Exposed') {
        Write-Host "    Status  : Exposed ($($result.Count) breach(es) found)" @Pen
        Write-Host "    Sources : $($result.Findings -join ', ')" @Pen
    }
    else {
        Write-Host "    Status  : Clean (0 breaches found)" @Cha
    }

    Write-Host "[4] Malicious Activity (Hudson Rock Cavalier)..." @Cha
    $cavalierResult = Get-CavalierEmail -Address $target

    if ($cavalierResult.Error) {
        Write-Host "    Status  : Error ($($cavalierResult.Error))" @Pen
    }
    elseif ($cavalierResult.Status -eq 'Compromised') {
        Write-Host "    Status  : Compromised ($($cavalierResult.Count) infostealer log(s) found)" @Pen
        foreach ($log in $cavalierResult.Findings) {
            $dateInfo = if ($log.date_compromised) { $log.date_compromised } else { 'Unknown date' }
            $stealerInfo = if ($log.stealer_family) {
                $log.stealer_family
            }
            elseif ($log.malware_path) {
                $log.malware_path
            }
            else {
                'Undisclosed stealer'
            }
            $osInfo = if ($log.operating_system) { $log.operating_system } else { 'Unknown OS' }
            Write-Host "    - Date: $dateInfo | Stealer: $stealerInfo | OS: $osInfo" @Pen
        }
    }
    else {
        Write-Host "    Status  : Clean (0 infostealer logs found)" @Cha
    }

    Write-Host "[5] Platforms..." @Cha
    Write-Host "    Status  : no data" @Pen
}