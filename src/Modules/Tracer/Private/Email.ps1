function Get-ContactInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $normalized = $Address.Trim().ToLower()
    $parts = $normalized -split '@', 2
    $localPart = $parts[0]
    $domain = $parts[1]

    # 1. Ekstraksi Username & Normalisasi Canonical Address
    $baseUser = ($localPart -split '\+', 2)[0]
    if ($domain -in @('gmail.com', 'googlemail.com')) {
        $cleanUser = $baseUser -replace '\.', ''
        $canonical = "$cleanUser@gmail.com"
    }
    else {
        $cleanUser = $baseUser
        $canonical = "$baseUser@$domain"
    }

    # 2. Klasifikasi Peran (Personal vs Role-Based)
    $rolePrefixes = @(
        'admin', 'administrator', 'info', 'support', 'help', 'sales',
        'marketing', 'hr', 'hrd', 'contact', 'billing', 'security',
        'abuse', 'postmaster', 'webmaster', 'noreply', 'no-reply', 'office', 'cs'
    )
    $accountRole = if ($cleanUser -in $rolePrefixes) { 'Role-Based' } else { 'Personal' }

    # 3. Klasifikasi Tipe Penyedia Layanan
    $disposableDomains = @(
        'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
        'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com'
    )

    $providerType = switch -Wildcard ($domain) {
        { $_ -in @('gmail.com', 'googlemail.com') } { 'Public Webmail (Google)'; break }
        { $_ -in @('yahoo.com', 'yahoo.co.id', 'ymail.com') } { 'Public Webmail (Yahoo)'; break }
        { $_ -in @('outlook.com', 'hotmail.com', 'live.com', 'msn.com') } { 'Public Webmail (Microsoft)'; break }
        { $_ -in @('icloud.com', 'me.com', 'mac.com') } { 'Public Webmail (Apple)'; break }
        { $_ -in @('proton.me', 'protonmail.com', 'pm.me', 'tuta.io', 'tutanota.com') } { 'Privacy-Focused Email'; break }
        { $_ -in $disposableDomains } { 'Disposable / Burner Email'; break }
        default { 'Custom / Organizational Domain' }
    }

    # 4. Pengecekan Profil Publik Gravatar (SHA-256 Hash Lookup)
    $gravatarResult = [PSCustomObject]@{
        Found       = $false
        DisplayName = $null
        Username    = $null
        Location    = $null
        ProfileUrl  = $null
    }

    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalized))
        $emailHash = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()

        $gravUri = "https://en.gravatar.com/$emailHash.json"
        $headers = @{ 'User-Agent' = 'Garuda-OSINT/1.0' }
        $gravResponse = Invoke-RestMethod -Uri $gravUri -Method Get -Headers $headers -TimeoutSec 8 -ErrorAction Stop

        if ($gravResponse.entry -and $gravResponse.entry.Count -gt 0) {
            $entry = $gravResponse.entry[0]
            $gravatarResult.Found = $true
            $gravatarResult.DisplayName = $entry.displayName
            $gravatarResult.Username = $entry.preferredUsername
            $gravatarResult.Location = $entry.currentLocation
            $gravatarResult.ProfileUrl = $entry.profileUrl
        }
    }
    catch {
        # 404 berarti tidak ada profil Gravatar terdaftar; abaikan secara halus
    }

    # 5. Pengecekan Kunci Publik OpenPGP (HKP Machine-Readable Lookup)
    $pgpResult = [PSCustomObject]@{
        Found   = $false
        UserId  = $null
        Created = $null
    }

    try {
        $encodedEmail = [System.Uri]::EscapeDataString($normalized)
        $pgpUri = "https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search=$encodedEmail"
        $pgpResponse = Invoke-RestMethod -Uri $pgpUri -Method Get -TimeoutSec 8 -ErrorAction Stop

        if ($pgpResponse -is [string] -and $pgpResponse -match '(?m)^pub:') {
            $pgpResult.Found = $true
            $lines = $pgpResponse -split "`n"

            foreach ($line in $lines) {
                if ($line -match '^pub:[^:]*:[^:]*:[^:]*:(\d+):') {
                    try {
                        $epoch = [long]$Matches[1]
                        $pgpResult.Created = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.ToString('yyyy-MM-dd')
                    }
                    catch {}
                }
                elseif ($line -match '^uid:([^:]+):') {
                    $pgpResult.UserId = [System.Uri]::UnescapeDataString($Matches[1])
                    break
                }
            }
        }
    }
    catch {
        # 404 berarti tidak ada kunci PGP publik terdaftar
    }

    return [PSCustomObject]@{
        Username     = $localPart
        Canonical    = $canonical
        AccountRole  = $accountRole
        ProviderType = $providerType
        Gravatar     = $gravatarResult
        PGP          = $pgpResult
    }
}

function Get-NetworkConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $normalized = $Address.Trim().ToLower()
    $domain = ($normalized -split '@', 2)[1]

    # Helper internal untuk kueri DNS (default resolver -> fallback 1.1.1.1)
    $InvokeDnsQuery = {
        param ([string]$QueryName, [string]$RecordType)
        try {
            return Resolve-DnsName -Name $QueryName -Type $RecordType -DnsOnly -ErrorAction Stop
        }
        catch {
            try {
                return Resolve-DnsName -Name $QueryName -Type $RecordType -Server '1.1.1.1' -DnsOnly -ErrorAction Stop
            }
            catch {
                return $null
            }
        }
    }

    # 1. Kueri MX Record
    $rawMx = & $InvokeDnsQuery -QueryName $domain -RecordType 'MX'
    $mxRecords = @()
    if ($rawMx) {
        $mxRecords = @($rawMx | Where-Object { $_.QueryType -eq 'MX' } | Sort-Object Preference)
    }

    if ($mxRecords.Count -eq 0) {
        return [PSCustomObject]@{
            Domain      = $domain
            HasMX       = $false
            MXCount     = 0
            PrimaryMX   = $null
            PrimaryMXIP = $null
            ReverseDNS  = $null
            Provider    = 'None (No MX Record)'
            SPF         = 'Not checked'
            DMARC       = 'Not checked'
            MTASTS      = 'Not checked'
            Error       = $null
        }
    }

    $primaryMx = $mxRecords[0].NameExchange.TrimEnd('.').ToLower()

    # 2. Sidik Jari Penyedia Mail Hosting berdasarkan Host MX
    $provider = switch -Wildcard ($primaryMx) {
        '*.google.com'              { 'Google Mail / Workspace'; break }
        '*.googlemail.com'          { 'Google Mail / Workspace'; break }
        '*.protection.outlook.com'  { 'Microsoft 365 (Exchange Online)'; break }
        '*.mail.eo.outlook.com'     { 'Microsoft 365 (Exchange Online)'; break }
        '*.zoho.com'                { 'Zoho Mail'; break }
        '*.zoho.eu'                 { 'Zoho Mail (EU)'; break }
        '*.zoho.in'                 { 'Zoho Mail (IN)'; break }
        '*.protonmail.ch'           { 'Proton Mail'; break }
        '*.mx.cloudflare.net'       { 'Cloudflare Email Routing'; break }
        '*.yahoodns.net'            { 'Yahoo Mail Infrastructure'; break }
        '*.icloud.com'              { 'Apple iCloud Mail'; break }
        '*.mimecast.com'            { 'Mimecast Secure Email Gateway'; break }
        '*.pphosted.com'            { 'Proofpoint Email Protection'; break }
        '*.barracudanetworks.com'   { 'Barracuda Email Security'; break }
        '*.secureserver.net'        { 'GoDaddy / Secureserver'; break }
        '*.yandex.net'              { 'Yandex 360 Mail'; break }
        '*.yandex.ru'               { 'Yandex 360 Mail'; break }
        default                     { 'Custom / Self-Hosted Mail Server' }
    }

    # 3. Resolusi IPv4 (A Record) & Reverse DNS (PTR) untuk Primary MX
    $primaryMxIp = $null
    $reverseDns = $null

    $aRecords = & $InvokeDnsQuery -QueryName $primaryMx -RecordType 'A'
    if ($aRecords) {
        $firstA = $aRecords | Where-Object { $_.QueryType -eq 'A' } | Select-Object -First 1
        if ($firstA -and $firstA.IPAddress) {
            $primaryMxIp = $firstA.IPAddress

            $ptrRecords = & $InvokeDnsQuery -QueryName $primaryMxIp -RecordType 'PTR'
            if ($ptrRecords) {
                $firstPtr = $ptrRecords | Where-Object { $_.QueryType -eq 'PTR' } | Select-Object -First 1
                if ($firstPtr -and $firstPtr.NameHost) {
                    $reverseDns = $firstPtr.NameHost.TrimEnd('.').ToLower()
                }
            }
        }
    }

    # 4. Audit Keamanan Email: SPF (TXT pada domain utama)
    $spfStatus = 'Missing'
    $rootTxt = & $InvokeDnsQuery -QueryName $domain -RecordType 'TXT'
    if ($rootTxt) {
        foreach ($rec in ($rootTxt | Where-Object { $_.QueryType -eq 'TXT' })) {
            $txtValue = ($rec.Strings -join '').Trim()
            if ($txtValue -match '^v=spf1\b') {
                if ($txtValue -match '-all\b') {
                    $spfStatus = 'Present / -all'
                }
                elseif ($txtValue -match '~all\b') {
                    $spfStatus = 'Present / ~all'
                }
                elseif ($txtValue -match '\?all\b') {
                    $spfStatus = 'Present / ?all'
                }
                elseif ($txtValue -match '\+all\b') {
                    $spfStatus = 'Weak / +all'
                }
                else {
                    $spfStatus = 'Present'
                }
                break
            }
        }
    }

    # 5. Audit Keamanan Email: DMARC (TXT pada _dmarc.<domain>)
    $dmarcStatus = 'Missing'
    $dmarcTxt = & $InvokeDnsQuery -QueryName "_dmarc.$domain" -RecordType 'TXT'
    if ($dmarcTxt) {
        foreach ($rec in ($dmarcTxt | Where-Object { $_.QueryType -eq 'TXT' })) {
            $txtValue = ($rec.Strings -join '').Trim()
            if ($txtValue -match '^v=DMARC1\b') {
                if ($txtValue -match '\bp=([a-zA-Z]+)') {
                    $dmarcStatus = "p=$($Matches[1].ToLower())"
                }
                else {
                    $dmarcStatus = 'Present'
                }
                break
            }
        }
    }

    # 6. Audit Enkripsi Transport: MTA-STS (TXT pada _mta-sts.<domain>)
    $mtastsStatus = 'Not configured'
    $mtastsTxt = & $InvokeDnsQuery -QueryName "_mta-sts.$domain" -RecordType 'TXT'
    if ($mtastsTxt) {
        foreach ($rec in ($mtastsTxt | Where-Object { $_.QueryType -eq 'TXT' })) {
            $txtValue = ($rec.Strings -join '').Trim()
            if ($txtValue -match '^v=STSv1\b') {
                $mtastsStatus = 'Enabled'
                break
            }
        }
    }

    return [PSCustomObject]@{
        Domain      = $domain
        HasMX       = $true
        MXCount     = $mxRecords.Count
        PrimaryMX   = $primaryMx
        PrimaryMXIP = $primaryMxIp
        ReverseDNS  = $reverseDns
        Provider    = $provider
        SPF         = $spfStatus
        DMARC       = $dmarcStatus
        MTASTS      = $mtastsStatus
        Error       = $null
    }
}

function Get-IntelX {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Address,

        [Parameter(Mandatory = $false)]
        [string]$ApiKey = $env:INTELX_API_KEY
    )

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        return [PSCustomObject]@{
            Source   = 'IntelligenceX'
            Status   = 'Skipped'
            Count    = 0
            Findings = @()
            Error    = 'INTELX_API_KEY not configured'
        }
    }

    $baseUrl = 'https://free.intelx.io'
    $headers = @{
        'x-key'        = $ApiKey.Trim()
        'Content-Type' = 'application/json'
    }

    $searchBody = @{
        term       = $Address
        maxresults = 10
        media      = 0
        sort       = 2   # Urutkan dari temuan terbaru
        terminate  = @()
    } | ConvertTo-Json -Compress

    try {
        # Tahap 1: Inisiasi pencarian untuk mendapatkan Search ID
        $initResponse = Invoke-RestMethod -Uri "$baseUrl/intelligent/search" -Method Post -Headers $headers -Body $searchBody -TimeoutSec 10 -ErrorAction Stop

        if (-not $initResponse.id) {
            return [PSCustomObject]@{
                Source   = 'IntelligenceX'
                Status   = 'Error'
                Count    = 0
                Findings = @()
                Error    = 'Failed to initialize search ID'
            }
        }

        $searchId = $initResponse.id
        $records = @()

        # Tahap 2: Polling singkat karena IntelX memproses pencarian secara asinkron
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Start-Sleep -Milliseconds 1200
            $resultResponse = Invoke-RestMethod -Uri "$baseUrl/intelligent/search/result?id=$searchId&limit=10" -Method Get -Headers $headers -TimeoutSec 10 -ErrorAction Stop

            if ($resultResponse.records -and $resultResponse.records.Count -gt 0) {
                $records = @($resultResponse.records)
                break
            }

            # Status 1 = selesai tanpa hasil, Status 2 = ID tidak valid
            if ($resultResponse.status -eq 1 -or $resultResponse.status -eq 2) {
                break
            }
        }

        # Tahap 3: Tutup sesi pencarian (gratis/no limit) agar slot concurrent tetap kosong
        try {
            Invoke-RestMethod -Uri "$baseUrl/intelligent/search/terminate?id=$searchId" -Method Get -Headers $headers -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}

        return [PSCustomObject]@{
            Source   = 'IntelligenceX'
            Status   = if ($records.Count -gt 0) { 'Exposed' } else { 'Clean' }
            Count    = $records.Count
            Findings = $records
            Error    = $null
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        $errMsg = if ($statusCode -eq 401) {
            'Invalid API Key (401)'
        }
        elseif ($statusCode -eq 402) {
            'Daily search credit exhausted (402)'
        }
        else {
            $_.Exception.Message
        }

        return [PSCustomObject]@{
            Source   = 'IntelligenceX'
            Status   = 'Error'
            Count    = 0
            Findings = @()
            Error    = $errMsg
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

    Write-Host "[1] Contact info..." @Cha
    $contact = Get-ContactInfo -Address $target

    Write-Host "    Username  : $($contact.Username)" @Pen
    if ($contact.Canonical -ne $target.Trim().ToLower()) {
        Write-Host "    Canonical : $($contact.Canonical) (Alias/dot normalized)" @Pen
    }
    Write-Host "    Type      : $($contact.AccountRole) / $($contact.ProviderType)" @Pen

    if ($contact.Gravatar.Found) {
        $gravDetails = @()
        if ($contact.Gravatar.DisplayName) { $gravDetails += $contact.Gravatar.DisplayName }
        if ($contact.Gravatar.Location) { $gravDetails += $contact.Gravatar.Location }
        $gravSummary = if ($gravDetails.Count -gt 0) { $gravDetails -join ' | ' } else { $contact.Gravatar.ProfileUrl }
        Write-Host "    Gravatar  : Found ($gravSummary)" @Pen
    }
    else {
        Write-Host "    Gravatar  : Not found" @Cha
    }

    if ($contact.PGP.Found) {
        $pgpUid = if ($contact.PGP.UserId) { $contact.PGP.UserId } else { 'Registered key' }
        $pgpDate = if ($contact.PGP.Created) { " [Created: $($contact.PGP.Created)]" } else { '' }
        Write-Host "    PGP Key   : Found ($pgpUid$pgpDate)" @Pen
    }
    else {
        Write-Host "    PGP Key   : Not found" @Cha
    }

    Write-Host "[2] Network Connection..." @Cha
    $net = Get-NetworkConnection -Address $target

    if (-not $net.HasMX) {
        Write-Host "    Domain    : $($net.Domain) (No MX record found)" @Pen
        Write-Host "    Status    : Inactive / Cannot receive email" @Pen
    }
    else {
        Write-Host "    Domain    : $($net.Domain) (Active MX - $($net.MXCount) record(s))" @Cha
        Write-Host "    Provider  : $($net.Provider)" @Pen
        $ipDisplay = if ($net.PrimaryMXIP) { " ($($net.PrimaryMXIP))" } else { "" }
        Write-Host "    Primary MX: $($net.PrimaryMX)$ipDisplay" @Pen
        if ($net.ReverseDNS -and ($net.ReverseDNS -ne $net.PrimaryMX)) {
            Write-Host "    ReverseDNS: $($net.ReverseDNS)" @Pen
        }
        Write-Host "    Security  : SPF ($($net.SPF)) | DMARC ($($net.DMARC)) | MTA-STS ($($net.MTASTS))" @Pen
    }

    Write-Host "[3] Hacker Activity (Intelligence X)..." @Cha
    $intelxResult = Get-IntelX -Address $target

    if ($intelxResult.Status -eq 'Skipped') {
        Write-Host "    Status  : Skipped ($($intelxResult.Error))" @Pen
    }
    elseif ($intelxResult.Error) {
        Write-Host "    Status  : Error ($($intelxResult.Error))" @Pen
    }
    elseif ($intelxResult.Status -eq 'Exposed') {
        Write-Host "    Status  : Exposed ($($intelxResult.Count) archive(s) found)" @Pen
        foreach ($item in $intelxResult.Findings) {
            $dateStr = if ($item.date) { ($item.date -split 'T')[0] } else { 'Unknown date' }
            $bucketStr = if ($item.bucket) { $item.bucket } else { 'Unknown bucket' }
            $nameStr = if ($item.name) { $item.name } else { 'Unnamed record' }
            Write-Host "    - [$dateStr] ($bucketStr) $nameStr" @Pen
        }
    }
    else {
        Write-Host "    Status  : Clean (0 records found)" @Cha
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

    Write-Host "[5] Platforms (XposedOrNot)..." @Cha
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
}