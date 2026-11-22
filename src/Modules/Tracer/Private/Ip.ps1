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
        Write-Host "[!] Dilewati: Alamat IP '$cleanIp' bukan IP publik yang dapat diperiksa." @penStyle
        return
    }

    $summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # 1. ABUSEIPDB REPUTATION CHECK
    # =========================================================================
    $apiKey = $env:ABUSEIPDB_API_KEY
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "`n[!] ABUSEIPDB_API_KEY belum diatur di Environment Variable (AbuseIPDB dilewati)." @penStyle
        Write-Host "    Contoh set sementara: `$env:ABUSEIPDB_API_KEY = '<ABUSEIPDB_API_KEY_ANDA>'" @chaStyle
    }
    else {
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
        $cacheDir  = Join-Path $env:TEMP "garuda_abuseipdb_cache"
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
                    }
                    else {
                        $parsed = $body | ConvertFrom-Json -ErrorAction Stop
                        $data   = $parsed.data
                        $body | Set-Content -Path $cacheFile -Encoding UTF8 -ErrorAction SilentlyContinue
                    }
                }
                finally {
                    $resp.Dispose()
                    $req.Dispose()
                }
            }
            catch {
                Write-Host "[!] Error koneksi AbuseIPDB: $(& $sanitizeText $_.Exception.Message)" @penStyle
            }
            finally {
                $client.Dispose()
                $handler.Dispose()
            }
        }

        if ($null -ne $data) {
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

            Write-Host "`n[*] Checking AbuseIPDB Reputation (${MaxAgeInDays}d | Cache: $cacheStatus)..." @chaStyle
            Write-Host "    Confidence Score : $scoreVal% ($totalRepVal reports | $distinctRep reporters)" @chaStyle
            Write-Host "    Top Categories   : $(& $sanitizeText $topCats)" @chaStyle
            Write-Host "    ISP / Usage      : $ispClean ($usageClean) [$countryClean]" @chaStyle
            Write-Host "    Last Reported    : $lastRepClean" @chaStyle

            $summaryRows.Add([PSCustomObject]@{
                Source    = 'AbuseIPDB'
                Detail    = "Confidence $scoreVal%"
                Indicator = "$totalRepVal reports | $(& $sanitizeText $topCats)"
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
        }
    }

    # =========================================================================
    # 2. VIRUSTOTAL THREAT INTELLIGENCE (API v3)
    # =========================================================================
    $vtApiKey = $env:VT_API_KEY
    if ([string]::IsNullOrWhiteSpace($vtApiKey)) {
        Write-Host "`n[!] VT_API_KEY belum diatur di Environment Variable (VirusTotal dilewati)." @penStyle
        Write-Host "    Contoh set sementara: `$env:VT_API_KEY = '<VT_API_KEY_ANDA>'" @chaStyle
    }
    else {
        $vtCacheDir = Join-Path $env:TEMP "garuda_vt_cache"
        if (-not (Test-Path $vtCacheDir)) {
            New-Item -Path $vtCacheDir -ItemType Directory -Force | Out-Null
        }
        $vtSafeFileKey = ($cleanIp -replace '[^a-zA-Z0-9._-]', '_') + "_vt.json"
        $vtCacheFile   = Join-Path $vtCacheDir $vtSafeFileKey

        $vtData        = $null
        $vtCacheStatus = "MISS"

        if (Test-Path $vtCacheFile) {
            $vtFileInfo = Get-Item $vtCacheFile
            if ($vtFileInfo.LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
                try {
                    $vtCachedRaw = Get-Content -Path $vtCacheFile -Raw -ErrorAction Stop
                    $vtCachedObj = $vtCachedRaw | ConvertFrom-Json -ErrorAction Stop
                    $vtData = if ($vtCachedObj.data) { $vtCachedObj.data } else { $vtCachedObj }
                    $vtCacheStatus = "HIT ($CacheHours h)"
                }
                catch {
                    $vtData = $null
                }
            }
        }

        if ($null -eq $vtData) {
            $vtHandler = [System.Net.Http.HttpClientHandler]::new()
            $vtHandler.UseCookies = $false
            $vtClient = [System.Net.Http.HttpClient]::new($vtHandler)
            $vtClient.Timeout = [TimeSpan]::FromSeconds(10)
            $vtClient.MaxResponseContentBufferSize = 2MB

            try {
                $vtUriStr = "https://www.virustotal.com/api/v3/ip_addresses/$([System.Uri]::EscapeDataString($cleanIp))"
                $vtReq = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $vtUriStr)
                $vtReq.Headers.Add("x-apikey", $vtApiKey.Trim())
                $vtReq.Headers.Add("Accept", "application/json")
                $vtReq.Headers.UserAgent.ParseAdd("Garuda-Threat-Observation/1.0")

                $vtResp = $vtClient.SendAsync($vtReq).GetAwaiter().GetResult()
                try {
                    $vtBody = $vtResp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    if (-not $vtResp.IsSuccessStatusCode) {
                        $vtErrMsg = "HTTP $([int]$vtResp.StatusCode)"
                        try {
                            $vtErrJson = $vtBody | ConvertFrom-Json
                            if ($vtErrJson.error -and $vtErrJson.error.message) {
                                $vtErrMsg = "$vtErrMsg - $($vtErrJson.error.message)"
                            }
                        } catch {}
                        Write-Host "`n[!] Gagal query VirusTotal: $(& $sanitizeText $vtErrMsg)" @penStyle
                    }
                    else {
                        $vtParsed = $vtBody | ConvertFrom-Json -ErrorAction Stop
                        $vtData   = $vtParsed.data
                        $vtBody | Set-Content -Path $vtCacheFile -Encoding UTF8 -ErrorAction SilentlyContinue
                    }
                }
                finally {
                    $vtResp.Dispose()
                    $vtReq.Dispose()
                }
            }
            catch {
                Write-Host "`n[!] Error koneksi VirusTotal: $(& $sanitizeText $_.Exception.Message)" @penStyle
            }
            finally {
                $vtClient.Dispose()
                $vtHandler.Dispose()
            }
        }

        if ($null -ne $vtData -and $vtData.attributes) {
            $vtAttrs = $vtData.attributes
            $vtStats = $vtAttrs.last_analysis_stats

            $vtMalicious  = if ($vtStats.malicious)  { [int]$vtStats.malicious }  else { 0 }
            $vtSuspicious = if ($vtStats.suspicious) { [int]$vtStats.suspicious } else { 0 }
            $vtHarmless   = if ($vtStats.harmless)   { [int]$vtStats.harmless }   else { 0 }
            $vtUndetected = if ($vtStats.undetected) { [int]$vtStats.undetected } else { 0 }
            $vtTimeout    = if ($vtStats.timeout)    { [int]$vtStats.timeout }    else { 0 }
            $vtTotal      = $vtMalicious + $vtSuspicious + $vtHarmless + $vtUndetected + $vtTimeout

            $vtNetwork = if ($vtAttrs.network)  { & $sanitizeText ([string]$vtAttrs.network) }  else { "N/A" }
            $vtAsn     = if ($vtAttrs.asn)      { "AS$($vtAttrs.asn)" }                        else { "N/A" }
            $vtAsOwner = if ($vtAttrs.as_owner) { & $sanitizeText ([string]$vtAttrs.as_owner) } else { "Unknown" }
            $vtCountry = if ($vtAttrs.country)  { & $sanitizeText ([string]$vtAttrs.country) }  else { "??" }

            $vtLastAnalysis = if ($vtAttrs.last_analysis_date) {
                [DateTimeOffset]::FromUnixTimeSeconds([long]$vtAttrs.last_analysis_date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            }
            else {
                "Unknown"
            }

            # Kumpulkan vendor yang memberi flag malicious/suspicious
            $flaggedVendors = [System.Collections.Generic.List[PSCustomObject]]::new()
            if ($vtAttrs.last_analysis_results) {
                foreach ($prop in $vtAttrs.last_analysis_results.PSObject.Properties) {
                    $vRes = $prop.Value
                    if ($vRes.category -in @('malicious', 'suspicious')) {
                        $vName   = & $sanitizeText $prop.Name
                        $vResult = if ($vRes.result) { & $sanitizeText ([string]$vRes.result) } else { & $sanitizeText ([string]$vRes.category) }
                        $flaggedVendors.Add([PSCustomObject]@{
                            Vendor   = $vName
                            Category = [string]$vRes.category
                            Result   = $vResult
                        })
                    }
                }
            }

            $topVendorNames = if ($flaggedVendors.Count -gt 0) {
                ($flaggedVendors | Select-Object -First 4 | ForEach-Object { "$($_.Vendor) ($($_.Result))" }) -join ", "
            }
            else {
                "Clean across vendors"
            }

            Write-Host "`n[*] Checking VirusTotal Intelligence (Cache: $vtCacheStatus)..." @chaStyle
            Write-Host "    Detection Ratio  : $vtMalicious/$vtTotal malicious ($vtSuspicious suspicious)" @chaStyle
            Write-Host "    Flagged Vendors  : $(& $sanitizeText $topVendorNames)" @chaStyle
            Write-Host "    Network / ASN    : $vtNetwork | $vtAsn ($vtAsOwner) [$vtCountry]" @chaStyle
            Write-Host "    Last Analysis    : $vtLastAnalysis" @chaStyle

            $summaryRows.Add([PSCustomObject]@{
                Source    = 'VirusTotal'
                Detail    = "Malicious $vtMalicious/$vtTotal"
                Indicator = if ($flaggedVendors.Count -gt 0) { "$($flaggedVendors.Count) flagged | $(& $sanitizeText $topVendorNames)" } else { "0 detections" }
            })

            foreach ($fv in ($flaggedVendors | Select-Object -First 5)) {
                $summaryRows.Add([PSCustomObject]@{
                    Source    = 'VTVendor'
                    Detail    = $fv.Vendor
                    Indicator = "$($fv.Category): $($fv.Result)"
                })
            }
        }
    }

    Write-Host "`n[+] Total Indicators Recorded: $($summaryRows.Count)" @chaStyle
    if ($summaryRows.Count -gt 0) {
        $summaryRows | Format-Table -Property Source, Detail, Indicator -AutoSize
    }
}