function hash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$target,

        [ValidateRange(1, 168)]
        [int]$CacheHours = 24
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $chaStyle = if ($script:Cha) { $script:Cha } elseif ($global:Cha) { $global:Cha } else { @{} }
    $penStyle = if ($script:Pen) { $script:Pen } elseif ($global:Pen) { $global:Pen } else { @{} }

    $sanitizeText = {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        return ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    }

    # Validasi ulang format hash (MD5, SHA-1, SHA-256, SHA-512)
    $cleanHash = $target.Trim().ToLowerInvariant()
    if ($cleanHash -notmatch '^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$') {
        Write-Host "[!] Format hash tidak valid (harus MD5/SHA-1/SHA-256/SHA-512): '$(& $sanitizeText $target)'" @penStyle
        return
    }

    $hashType = switch ($cleanHash.Length) {
        32  { 'MD5' }
        40  { 'SHA-1' }
        64  { 'SHA-256' }
        128 { 'SHA-512' }
    }

    $vtApiKey = $env:VT_API_KEY
    if ([string]::IsNullOrWhiteSpace($vtApiKey)) {
        Write-Host "[!] VT_API_KEY belum diatur di Environment Variable." @penStyle
        Write-Host "    Contoh set sementara: `$env:VT_API_KEY = '<VT_API_KEY_ANDA>'" @chaStyle
        return
    }

    $summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Cache lokal per hash untuk menghemat kuota API VirusTotal
    $vtCacheDir = Join-Path $env:TEMP "garuda_vt_hash_cache"
    if (-not (Test-Path $vtCacheDir)) {
        New-Item -Path $vtCacheDir -ItemType Directory -Force | Out-Null
    }
    $vtCacheFile   = Join-Path $vtCacheDir "$($cleanHash)_vt.json"
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
        $vtClient.MaxResponseContentBufferSize = 4MB

        try {
            $vtUriStr = "https://www.virustotal.com/api/v3/files/$([System.Uri]::EscapeDataString($cleanHash))"
            $vtReq = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $vtUriStr)
            $vtReq.Headers.Add("x-apikey", $vtApiKey.Trim())
            $vtReq.Headers.Add("Accept", "application/json")
            $vtReq.Headers.UserAgent.ParseAdd("Garuda-Threat-Observation/1.0")

            $vtResp = $vtClient.SendAsync($vtReq).GetAwaiter().GetResult()
            try {
                $vtBody = $vtResp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ([int]$vtResp.StatusCode -eq 404) {
                    Write-Host "`n[*] Checking VirusTotal File Intelligence ($hashType | Cache: MISS)..." @chaStyle
                    Write-Host "    Status           : Not Found in VirusTotal database (belum pernah dianalisis)" @chaStyle
                    return
                }
                elseif (-not $vtResp.IsSuccessStatusCode) {
                    $vtErrMsg = "HTTP $([int]$vtResp.StatusCode)"
                    try {
                        $vtErrJson = $vtBody | ConvertFrom-Json
                        if ($vtErrJson.error -and $vtErrJson.error.message) {
                            $vtErrMsg = "$vtErrMsg - $($vtErrJson.error.message)"
                        }
                    } catch {}
                    Write-Host "[!] Gagal query VirusTotal: $(& $sanitizeText $vtErrMsg)" @penStyle
                    return
                }

                $vtParsed = $vtBody | ConvertFrom-Json -ErrorAction Stop
                $vtData   = $vtParsed.data
                $vtBody | Set-Content -Path $vtCacheFile -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            finally {
                $vtResp.Dispose()
                $vtReq.Dispose()
            }
        }
        catch {
            Write-Host "[!] Error koneksi VirusTotal: $(& $sanitizeText $_.Exception.Message)" @penStyle
            return
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

        $threatLabel = if ($vtAttrs.popular_threat_classification -and $vtAttrs.popular_threat_classification.suggested_threat_label) {
            & $sanitizeText ([string]$vtAttrs.popular_threat_classification.suggested_threat_label)
        }
        elseif ($vtMalicious -eq 0 -and $vtSuspicious -eq 0) {
            "Clean / Undetected"
        }
        else {
            "Unclassified Threat"
        }

        $fileName = if ($vtAttrs.meaningful_name) {
            & $sanitizeText ([string]$vtAttrs.meaningful_name)
        }
        elseif ($vtAttrs.names -and $vtAttrs.names.Count -gt 0) {
            & $sanitizeText ([string]$vtAttrs.names[0])
        }
        else {
            "Unknown filename"
        }

        $fileType = if ($vtAttrs.type_description) { & $sanitizeText ([string]$vtAttrs.type_description) } else { "Unknown type" }
        $fileSize = if ($null -ne $vtAttrs.size) {
            $bytesVal = [long]$vtAttrs.size
            if ($bytesVal -ge 1MB) { "{0:N2} MB" -f ($bytesVal / 1MB) }
            elseif ($bytesVal -ge 1KB) { "{0:N2} KB" -f ($bytesVal / 1KB) }
            else { "$bytesVal B" }
        }
        else {
            "Unknown size"
        }

        $firstSeen = if ($vtAttrs.first_submission_date) {
            [DateTimeOffset]::FromUnixTimeSeconds([long]$vtAttrs.first_submission_date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        }
        else {
            "Unknown"
        }

        $lastAnalysis = if ($vtAttrs.last_analysis_date) {
            [DateTimeOffset]::FromUnixTimeSeconds([long]$vtAttrs.last_analysis_date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        }
        else {
            "Unknown"
        }

        # Kumpulkan vendor yang mendeteksi & urutkan: malicious diprioritaskan di atas suspicious
        $flaggedVendors = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($vtAttrs.last_analysis_results) {
            foreach ($prop in $vtAttrs.last_analysis_results.PSObject.Properties) {
                $vRes = $prop.Value
                if ($vRes.category -in @('malicious', 'suspicious')) {
                    $vName     = & $sanitizeText $prop.Name
                    $vResult   = if ($vRes.result) { & $sanitizeText ([string]$vRes.result) } else { & $sanitizeText ([string]$vRes.category) }
                    $sortOrder = if ($vRes.category -eq 'malicious') { 1 } else { 2 }
                    $flaggedVendors.Add([PSCustomObject]@{
                        Priority = $sortOrder
                        Vendor   = $vName
                        Category = [string]$vRes.category
                        Result   = $vResult
                    })
                }
            }
        }

        $sortedVendors = $flaggedVendors | Sort-Object Priority, Vendor

        Write-Host "`n[*] Checking VirusTotal File Intelligence ($hashType | Cache: $vtCacheStatus)..." @chaStyle
        Write-Host "    Detection Ratio  : $vtMalicious/$vtTotal malicious ($vtSuspicious suspicious)" @chaStyle
        Write-Host "    Threat Label     : $threatLabel" @chaStyle
        Write-Host "    File Info        : $fileName ($fileType | $fileSize)" @chaStyle
        Write-Host "    First / Last Seen: $firstSeen | $lastAnalysis" @chaStyle

        $summaryRows.Add([PSCustomObject]@{
            Source    = 'VirusTotal'
            Detail    = "Malicious $vtMalicious/$vtTotal"
            Indicator = "$threatLabel | $fileName"
        })

        if ($vtAttrs.sha256 -and ($cleanHash.Length -ne 64)) {
            $summaryRows.Add([PSCustomObject]@{
                Source    = 'FileHash'
                Detail    = 'SHA-256'
                Indicator = & $sanitizeText ([string]$vtAttrs.sha256)
            })
        }

        foreach ($fv in ($sortedVendors | Select-Object -First 6)) {
            $summaryRows.Add([PSCustomObject]@{
                Source    = 'VTVendor'
                Detail    = $fv.Vendor
                Indicator = "$($fv.Category): $($fv.Result)"
            })
        }
    }

    Write-Host "`n[+] Total Indicators Recorded: $($summaryRows.Count)" @chaStyle
    if ($summaryRows.Count -gt 0) {
        $summaryRows | Format-Table -Property Source, Detail, Indicator -AutoSize
    }
}