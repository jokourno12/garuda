function ip{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$target,

        [ValidateRange(1, 365)]
        [int]$MaxAgeInDays = 90,

        [ValidateRange(1, 168)]
        [int]$CacheHours = 12
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $chaStyle = if ($script:Cha) { $script:Cha } elseif ($global:Cha) { $global:Cha } else { @{} }
    $penStyle = if ($script:Pen) { $script:Pen } elseif ($global:Pen) { $global:Pen } else { @{} }

    $sanitizeText = {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        return ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    }

    # Validasi format IP & cegah query ke IP lokal/privat/loopback
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($target.Trim(), [ref]$parsedIp)) {
        Write-Host "[!] Format alamat IP tidak valid: '$(& $sanitizeText $target)'" @penStyle
        return
    }

    $bytes = $parsedIp.GetAddressBytes()
    $isPrivateOrLocal = $false
    if ([System.Net.IPAddress]::IsLoopback($parsedIp)) { $isPrivateOrLocal = $true }
    elseif ($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -in 0, 10, 127) { $isPrivateOrLocal = $true }
        elseif ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { $isPrivateOrLocal = $true }
        elseif ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { $isPrivateOrLocal = $true }
        elseif ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { $isPrivateOrLocal = $true }
        elseif ($bytes[0] -ge 224) { $isPrivateOrLocal = $true }
    }
    elseif ($parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($parsedIp.IsIPv6LinkLocal -or $parsedIp.IsIPv6SiteLocal -or $parsedIp.IsIPv6Multicast) { $isPrivateOrLocal = $true }
        elseif (($bytes[0] -band 0xFE) -eq 0xFC) { $isPrivateOrLocal = $true }
    }

    $cleanIp = & $sanitizeText $parsedIp.ToString()
    if ($isPrivateOrLocal) {
        Write-Host "[!] Dilewati: Alamat IP '$cleanIp' bukan IP publik yang dapat dicek di AbuseIPDB." @penStyle
        return
    }

    # Baca API key dari Environment Variable (lebih aman daripada hardcode di skrip)
    $apiKey = $env:ABUSEIPDB_API_KEY
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "[!] ABUSEIPDB_API_KEY belum diatur di Environment Variable." @penStyle
        Write-Host "    Contoh set sementara: `$env:ABUSEIPDB_API_KEY = '<API_KEY_ANDA>'" @chaStyle
        return
    }

    # Pemetaan kategori umum AbuseIPDB agar mudah dibaca analis
    $categoryMap = @{
        1  = 'DNS Compromise'; 2 = 'DNS Poisoning'; 3 = 'Fraud Orders'; 4 = 'DDoS Attack'
        5  = 'FTP Brute-Force'; 6 = 'Ping of Death'; 7 = 'Phishing'; 8 = 'Fraud VoIP'
        9  = 'Open Proxy'; 10 = 'Web Spam'; 11 = 'Email Spam'; 12 = 'Blog Spam'
        13 = 'VPN IP'; 14 = 'Port Scan'; 15 = 'Hacking'; 16 = 'SQL Injection'
        17 = 'Spoofing'; 18 = 'SSH Brute-Force'; 19 = 'Web Attack'; 20 = 'Brute-Force'
        21 = 'Bad Web Bot'; 22 = 'Exploited Host'; 23 = 'Web App Attack'; 24 = 'SSH'
        25 = 'IoT Targeted'
    }

    # Cache lokal per IP + rentang hari untuk menghemat kuota API harian
    $cacheDir = Join-Path ([System.IO.Path]::GetTempPath()) "garuda_abuseipdb_cache"
    if (-not (Test-Path $cacheDir)) {
        New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
    }
    $safeFileKey = ($cleanIp -replace '[^a-zA-Z0-9._-]', '_') + "_${MaxAgeInDays}d.json"
    $cacheFile   = Join-Path $cacheDir $safeFileKey

    $data        = $null
    $cacheStatus = "MISS"

    if (Test-Path $cacheFile) {
        $fileInfo = Get-Item $cacheFile
        if ($fileInfo.LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
            try {
                $cachedRaw = Get-Content -Path $cacheFile -Raw -ErrorAction Stop
                $cachedObj = $cachedRaw | ConvertFrom-Json -ErrorAction Stop
                $data = if ($cachedObj.data) { $cachedObj.data } else { $cachedObj }
                $cacheStatus = "HIT ($CacheHours h)"
            }
            catch {
                $data = $null
            }
        }
    }

    if ($null -eq $data) {
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.UseCookies = $false
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(10)
        $client.MaxResponseContentBufferSize = 1MB

        try {
            $uriStr = "https://api.abuseipdb.com/api/v2/check?ipAddress=$([System.Uri]::EscapeDataString($cleanIp))&maxAgeInDays=$MaxAgeInDays&verbose=true"
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uriStr)
            $req.Headers.Add("Key", $apiKey.Trim())
            $req.Headers.Add("Accept", "application/json")
            $req.Headers.UserAgent.ParseAdd("Garuda-Threat-Observation/1.0")

            $resp = $client.SendAsync($req).GetAwaiter().GetResult()
            try {
                $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if (-not $resp.IsSuccessStatusCode) {
                    $errMsg = "HTTP $([int]$resp.StatusCode)"
                    try {
                        $errJson = $body | ConvertFrom-Json
                        if ($errJson.errors -and $errJson.errors[0].detail) {
                            $errMsg = "$errMsg - $($errJson.errors[0].detail)"
                        }
                    } catch {}
                    Write-Host "[!] Gagal query AbuseIPDB: $(& $sanitizeText $errMsg)" @penStyle
                    return
                }

                $parsed = $body | ConvertFrom-Json -ErrorAction Stop
                $data   = $parsed.data
                $body | Set-Content -Path $cacheFile -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            finally {
                $resp.Dispose()
                $req.Dispose()
            }
        }
        catch {
            Write-Host "[!] Error koneksi AbuseIPDB: $(& $sanitizeText $_.Exception.Message)" @penStyle
            return
        }
        finally {
            $client.Dispose()
            $handler.Dispose()
        }
    }

    # Hitung ringkasan kategori dari riwayat laporan (jika tersedia)
    $catCounts = @{}
    if ($data.reports) {
        foreach ($rep in $data.reports) {
            if ($rep.categories) {
                foreach ($cId in $rep.categories) {
                    $idInt = [int]$cId
                    if (-not $catCounts.ContainsKey($idInt)) { $catCounts[$idInt] = 0 }
                    $catCounts[$idInt]++
                }
            }
        }
    }

    $topCats = if ($catCounts.Count -gt 0) {
        ($catCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object {
            $label = if ($categoryMap.ContainsKey($_.Key)) { $categoryMap[$_.Key] } else { "Cat $($_.Key)" }
            "$label ($($_.Value))"
        }) -join ", "
    }
    else {
        "None recorded"
    }

    $scoreVal     = [int]$data.abuseConfidenceScore
    $totalRepVal  = [int]$data.totalReports
    $distinctRep  = if ($data.numDistinctUsers) { [int]$data.numDistinctUsers } else { 0 }
    $ispClean     = & $sanitizeText ([string]$data.isp)
    $usageClean   = & $sanitizeText ([string]$data.usageType)
    $countryClean = & $sanitizeText ([string]$data.countryCode)
    $lastRepClean = if ($data.lastReportedAt) { & $sanitizeText ([string]$data.lastReportedAt) } else { "Never" }
    $scoreStyle   = if ($scoreVal -ge 80) { $penStyle } else { $chaStyle }

    Write-Host "`n[*] Checking AbuseIPDB Reputation (${MaxAgeInDays}d | Cache: $cacheStatus)..." @chaStyle
    Write-Host "    Confidence Score : $scoreVal% ($totalRepVal reports | $distinctRep reporters)" @scoreStyle
    Write-Host "    Top Categories   : $(& $sanitizeText $topCats)" @chaStyle
    Write-Host "    ISP / Usage      : $ispClean ($usageClean) [$countryClean]" @chaStyle
    Write-Host "    Last Reported    : $lastRepClean" @chaStyle

    $summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $summaryRows.Add([PSCustomObject]@{
        Source    = 'AbuseIPDB'
        Detail    = "Confidence $scoreVal%"
        Indicator = "$totalRepVal reports | $topCats"
    })

    if ($data.reports) {
        foreach ($rep in ($data.reports | Select-Object -First 5)) {
            $repNames = if ($rep.categories) {
                ($rep.categories | ForEach-Object {
                    $k = [int]$_
                    if ($categoryMap.ContainsKey($k)) { $categoryMap[$k] } else { "Cat $k" }
                }) -join ", "
            } else { "Uncategorized" }

            $repTime = & $sanitizeText ([string]$rep.reportedAt)
            $summaryRows.Add([PSCustomObject]@{
                Source    = 'ReportLog'
                Detail    = $repTime
                Indicator = & $sanitizeText $repNames
            })
        }
    }

    Write-Host "`n[+] Total Indicators Recorded: $($summaryRows.Count)" @chaStyle
    $summaryRows | Format-Table -Property Source, Detail, Indicator -AutoSize

    # ==========================================================
    # Konklusi Dinamis Satu Paragraf
    # ==========================================================
    $affiliationPart = if (-not [string]::IsNullOrWhiteSpace($ispClean) -and -not [string]::IsNullOrWhiteSpace($usageClean)) {
        "yang terafiliasi dengan $ispClean ($usageClean) "
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ispClean)) {
        "yang terafiliasi dengan $ispClean "
    }
    elseif (-not [string]::IsNullOrWhiteSpace($usageClean)) {
        "dengan tipe jaringan $usageClean "
    }
    else {
        ""
    }

    if ($scoreVal -eq 0 -and $totalRepVal -eq 0) {
        $conclusionParagraph = "Alamat IP $cleanIp ${affiliationPart}terpantau bersih dengan skor kepercayaan 0% dan tidak memiliki catatan laporan aktivitas berbahaya dalam $MaxAgeInDays hari terakhir, sehingga saat ini tidak diperlukan tindakan pembatasan akses maupun pemblokiran pada infrastruktur jaringan."
    }
    else {
        $riskLevelText = if ($scoreVal -ge 80) {
            "tinggi"
        }
        elseif ($scoreVal -ge 25) {
            "sedang"
        }
        else {
            "rendah"
        }

        $reportLogRows = @($summaryRows | Where-Object { $_.Source -eq 'ReportLog' })
        $parsedDates   = [System.Collections.Generic.List[DateTime]]::new()
        $rawDateTokens = [System.Collections.Generic.List[string]]::new()

        foreach ($logRow in $reportLogRows) {
            if (-not [string]::IsNullOrWhiteSpace($logRow.Detail)) {
                $dtOut = [DateTime]::MinValue
                if ([DateTime]::TryParse($logRow.Detail, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dtOut)) {
                    $parsedDates.Add($dtOut)
                }
                else {
                    $rawDateTokens.Add(($logRow.Detail -split '\s+')[0])
                }
            }
        }

        $activityWindowText = if ($parsedDates.Count -gt 0) {
            $sortedDates = $parsedDates | Sort-Object
            $earliestStr = $sortedDates[0].ToString('MM/dd/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
            $latestStr   = $sortedDates[-1].ToString('MM/dd/yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
            if ($earliestStr -eq $latestStr) {
                "yang tercatat aktif pada $latestStr"
            }
            else {
                "yang tercatat aktif sejak $earliestStr hingga $latestStr"
            }
        }
        elseif ($rawDateTokens.Count -gt 0) {
            if ($rawDateTokens[0] -eq $rawDateTokens[-1]) {
                "yang tercatat aktif pada $($rawDateTokens[0])"
            }
            else {
                "yang tercatat aktif sejak $($rawDateTokens[-1]) hingga $($rawDateTokens[0])"
            }
        }
        elseif ($lastRepClean -ne 'Never') {
            "dengan laporan terakhir tercatat pada $lastRepClean"
        }
        else {
            "dalam $MaxAgeInDays hari terakhir"
        }

        $uniqueActivities = [System.Collections.Generic.List[string]]::new()
        if ($catCounts.Count -gt 0) {
            foreach ($entry in ($catCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3)) {
                $catTitle = if ($categoryMap.ContainsKey($entry.Key)) { $categoryMap[$entry.Key] } else { "Cat $($entry.Key)" }
                if (-not $uniqueActivities.Contains($catTitle)) {
                    $uniqueActivities.Add($catTitle)
                }
            }
        }
        foreach ($logRow in $reportLogRows) {
            if (-not [string]::IsNullOrWhiteSpace($logRow.Indicator) -and $logRow.Indicator -ne 'Uncategorized') {
                foreach ($actName in ($logRow.Indicator -split ',\s*')) {
                    $trimmedAct = $actName.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($trimmedAct) -and -not $uniqueActivities.Contains($trimmedAct)) {
                        $uniqueActivities.Add($trimmedAct)
                    }
                }
            }
        }

        $activitySummaryText = if ($uniqueActivities.Count -eq 1) {
            "didominasi aktivitas $($uniqueActivities[0])"
        }
        elseif ($uniqueActivities.Count -eq 2) {
            "didominasi aktivitas $($uniqueActivities[0]) serta $($uniqueActivities[1])"
        }
        elseif ($uniqueActivities.Count -gt 2) {
            $leadingActivities = ($uniqueActivities[0..($uniqueActivities.Count - 2)] -join ', ')
            "didominasi aktivitas $leadingActivities, serta $($uniqueActivities[-1])"
        }
        else {
            "dengan catatan laporan aktivitas mencurigakan"
        }

        $mitigationText = if ($usageClean -match 'Fixed Line ISP|Mobile ISP|ISP') {
            "sehingga karena berasal dari jaringan ISP residensial/satelit yang umumnya berbagi IP dinamis (CGNAT), mitigasi yang disarankan adalah menerapkan rate-limiting atau temporary ban pada layanan terdampak dibandingkan pemblokiran permanen."
        }
        elseif ($usageClean -match 'Data Center|Web Hosting|Transit|Commercial') {
            "sehingga karena berasal dari infrastruktur server/hosting terdedikasi, mitigasi yang disarankan adalah menerapkan pemblokiran permanen pada firewall atau WAF serta memperketat pemantauan log akses."
        }
        elseif ($usageClean -match 'Content Delivery Network|Search Engine|Reserved') {
            "sehingga karena teridentifikasi sebagai infrastruktur layanan pihak ketiga/CDN khusus, disarankan memverifikasi keabsahan lalu lintas sebelum menerapkan pembatasan akses agar tidak memutus layanan sah."
        }
        else {
            "sehingga mitigasi yang disarankan adalah menerapkan pembatasan akses (rate-limiting atau pemblokiran sementara) serta pemantauan ketat pada layanan terdampak."
        }

        $conclusionParagraph = "Alamat IP $cleanIp ${affiliationPart}berada pada tingkat risiko $riskLevelText dengan skor kepercayaan $scoreVal% dari $totalRepVal laporan $activityWindowText, $activitySummaryText, $mitigationText"
    }

    Write-Host "[*] Conclusion: $conclusionParagraph" @scoreStyle
}
