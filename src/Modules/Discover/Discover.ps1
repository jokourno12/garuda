. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'InternetProtocolRange.ps1'))"

function discover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    $localIPs = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
        ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
        Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
        ForEach-Object { $_.Address.ToString() }

    $hostResults = [System.Collections.ArrayList]::new()
    $showMac = $false
    $runClassification = $false

    $reachableTargets = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()

    foreach ($target in $targets) {
        if ($target -match "/") {
            $ipRange = internetProtocolRange -subnet $target

            $ipRange | ForEach-Object -Parallel {
                $ip = $_
                $localResult = $using:reachableTargets
                $method = "None"

                Write-Progress -Activity "Checking if $ip is reachable"
                $pingSender = [System.Net.NetworkInformation.Ping]::new()
                
                try {
                    for ($i = 0; $i -lt 2; $i++) {
                        $reply = $pingSender.Send($ip, 1000)
                        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                            $ttl = if ($null -ne $reply.Options) { $reply.Options.Ttl } else { $null }
                            
                            if ($null -eq $ttl) {
                                $pingOut = ping -c 1 -W 1 $ip 2>$null | Out-String
                                if ($pingOut -match 'ttl=(\d+)') {
                                    $ttl = $matches[1]
                                } else {
                                    $ttl = "?"
                                }
                            }

                            $method = "ICMP (TTL:$ttl)"
                            break
                        }
                    }
                } catch { } finally { $pingSender.Dispose() }

                if ($method -eq "None") {
                    foreach ($port in @(443, 80)) {
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        try {
                            $connectResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
                            $success = $connectResult.AsyncWaitHandle.WaitOne(1000, $true)
                            if ($success -and $tcpClient.Connected) {
                                $tcpClient.EndConnect($connectResult)
                                $method = "TCP/$port"
                                break
                            }
                        } catch {} finally {
                            $tcpClient.Close()
                            $tcpClient.Dispose()
                        }
                    }
                }
                $localResult[$ip] = $method
            } @ThrottleCreat

            $reachableCount = 0

            if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                $hasReachable = $false
                foreach ($ip in $ipRange) { 
                    if ($reachableTargets.ContainsKey($ip) -and $reachableTargets[$ip] -ne "None") { $hasReachable = $true; break } 
                }
                if ($hasReachable) {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    if ((Read-Host " [*] Show MAC Address? (Y/N)") -match '^[Yy]') { $showMac = $true }
                    if ((Read-Host " [*] Discover Switch & Router / Device OS? (Y/N)") -match '^[Yy]') { $runClassification = $true }
                }
            }

            foreach ($ip in $ipRange | Sort-Object) {
                $detectedMethod = $reachableTargets[$ip]
                if ($detectedMethod -ne "None") {
                    $dto = [HostResult]::new($ip)
                    $dto.IsReachable = $true
                    
                    if ($detectedMethod -match 'ICMP \(TTL:(\d+)\)') {
                        $dto.Protocol = "ICMP"
                        $dto.TTL = [int]$matches[1]
                    } else {
                        $dto.Protocol = $detectedMethod
                    }

                    if ($showMac -or $runClassification) {
                        $macResult = $null
                        if ($IsWindows -and (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue)) {
                            $macResult = (Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                        } elseif ($IsLinux -and (Get-Command ip -ErrorAction SilentlyContinue)) {
                            $arpLine = ip neigh show $ip 2>$null | Out-String
                            if ($arpLine -match '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}') {
                                $macResult = $matches[0]
                            }
                        }
                        $dto.MACAddress = if ($macResult) { $macResult } else { "N/A" }
                    }
                    
                    if ($runClassification) {
                        $isLocal = $localIPs -contains $ip
                        $dto.InferClassification($isLocal)
                    }

                    [void]$hostResults.Add($dto)
                    $reachableCount++
                }
            }

            if ($reachableCount -eq 0) {
                Write-Host " [*] Layer 3 ICMP Checked." @Dim
                Write-Host " [*] Layer 4 TCP Checked." @Dim
                Write-Host " [*] All IPs in subnet $target are not reachable." @Cha
            }
        }
        else {
            $method = "None"
            $pingSingle = [System.Net.NetworkInformation.Ping]::new()
            
            try {
                for ($i = 0; $i -lt 2; $i++) {
                    $reply = $pingSingle.Send($target, 1000)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $ttl = if ($null -ne $reply.Options) { $reply.Options.Ttl } else { $null }

                        if ($null -eq $ttl) {
                            $pingOut = ping -c 1 -W 1 $target 2>$null | Out-String
                            if ($pingOut -match 'ttl=(\d+)') {
                                $ttl = $matches[1]
                            } else {
                                $ttl = "?"
                            }
                        }

                        $method = "ICMP (TTL:$ttl)"
                        break
                    }
                }
            } catch { } finally { $pingSingle.Dispose() }
            
            if ($method -eq "None") {
                Write-Host " [*] Layer ICMP possible blocked for $target." @Cha
                Write-Host " [*] Attempting Layer 4 (TCP)..." @Inc

                foreach ($port in @(443, 80)) {
                    $tcpClientSingle = [System.Net.Sockets.TcpClient]::new()
                    try {
                        $connectResult = $tcpClientSingle.BeginConnect($target, $port, $null, $null)
                        $success = $connectResult.AsyncWaitHandle.WaitOne(1000, $true)
                        if ($success -and $tcpClientSingle.Connected) {
                            $tcpClientSingle.EndConnect($connectResult) 
                            $method = "TCP/$port"
                            break
                        }
                    } catch {} finally {
                        $tcpClientSingle.Close()
                        $tcpClientSingle.Dispose()
                    }
                }
            }

            if ($method -ne "None") {
                if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    if ((Read-Host " [*] Show MAC Address? (Y/N)") -match '^[Yy]') { $showMac = $true }
                    if ((Read-Host " [*] Discover Switch & Router / Device OS? (Y/N)") -match '^[Yy]') { $runClassification = $true }
                }

                $dto = [HostResult]::new($target)
                $dto.IsReachable = $true
                
                if ($method -match 'ICMP \(TTL:(\d+)\)') {
                    $dto.Protocol = "ICMP"
                    $dto.TTL = [int]$matches[1]
                } else {
                    $dto.Protocol = $method
                }

                if ($showMac -or $runClassification) { 
                    $macResult = $null
                    if ($IsWindows -and (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue)) {
                        $macResult = (Get-NetNeighbor -IPAddress $target -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                    } elseif ($IsLinux -and (Get-Command ip -ErrorAction SilentlyContinue)) {
                        $arpLine = ip neigh show $target 2>$null | Out-String
                        if ($arpLine -match '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}') {
                            $macResult = $matches[0]
                        }
                    }
                    $dto.MACAddress = if ($macResult) { $macResult } else { "N/A" }
                }

                if ($runClassification) {
                    $isLocal = $localIPs -contains $target
                    $dto.InferClassification($isLocal)
                }

                [void]$hostResults.Add($dto)
                $reachableTargets[$target] = $method 
            }
            else {
                Write-Host "$target is not reachable" @Cha
                $reachableTargets[$target] = "None"
            }
        }
    }

    if ($VerbosePreference -ne 'SilentlyContinue') {
        Write-Host "`nReachable Hosts:" @Net
        foreach ($ip in $reachableTargets.Keys | Sort-Object) {
            if ($reachableTargets[$ip] -ne "None") {
                Write-Host " - $ip ($($reachableTargets[$ip]))"
            }
        }
    }

    hostResultTable -Results $hostResults -ShowMac $showMac -ShowClassification $runClassification

    # ==========================================================
    # Konklusi Dinamis Satu Paragraf (Network Discovery Summary)
    # ==========================================================
    $getClassValue = {
        param($obj)
        foreach ($propName in @('InferredClassification', 'Classification', 'DeviceType', 'OS', 'Category', 'Role')) {
            $prop = $obj.PSObject.Properties[$propName]
            if ($null -ne $prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                return ([string]$prop.Value).Trim()
            }
        }
        return $null
    }

    $totalScannedCount   = $reachableTargets.Count
    $totalReachableCount = $hostResults.Count
    $hasSubnetTarget     = ($targets | Where-Object { $_ -match '/' }).Count -gt 0
    $isSingleTargetScan  = ($targets.Count -eq 1) -and (-not $hasSubnetTarget)

    $internalTargetList = @($targets | Where-Object { $_ -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' })
    $publicTargetList   = @($targets | Where-Object { $_ -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' })

    $scopeSegmentText = if ($internalTargetList.Count -gt 0 -and $publicTargetList.Count -eq 0) {
        "internal"
    }
    elseif ($publicTargetList.Count -gt 0 -and $internalTargetList.Count -eq 0) {
        "publik"
    }
    else {
        "campuran (internal dan publik)"
    }

    $targetDescriptor = if ($targets.Count -eq 1) {
        if ($hasSubnetTarget) {
            "subnet $scopeSegmentText $($targets[0])"
        }
        else {
            "target $scopeSegmentText $($targets[0])"
        }
    }
    else {
        "$($targets.Count) cakupan target $scopeSegmentText ($($targets -join ', '))"
    }

    if ($totalReachableCount -eq 0) {
        $mitigationUnreachable = if ($scopeSegmentText -eq "internal") {
            "sehingga kemungkinan segmen jaringan atau host tersebut dalam kondisi tidak aktif, terisolasi oleh aturan VLAN/firewall lokal, atau tidak memiliki rute balik ke mesin pemindai."
        }
        else {
            "sehingga kemungkinan host sedang tidak aktif, dilindungi kebijakan firewall perimeter yang memblokir ICMP serta port web standar, atau tidak dapat dijangkau dari jalur jaringan saat ini."
        }

        $conclusionParagraph = "Pemindaian terhadap $targetDescriptor tidak menemukan satu pun host yang merespons baik melalui pemeriksaan Layer 3 ICMP maupun fallback Layer 4 TCP (port 80/443) dari total $totalScannedCount alamat yang diperiksa, $mitigationUnreachable"
    }
    else {
        # Pisahkan alamat Broadcast dari perangkat aktif unicast
        $broadcastHosts = @($hostResults | Where-Object {
            (($_.MACAddress -replace ':', '-') -eq 'FF-FF-FF-FF-FF-FF') -or ((& $getClassValue $_) -eq 'Broadcast')
        })
        $activeDevices = @($hostResults | Where-Object {
            (($_.MACAddress -replace ':', '-') -ne 'FF-FF-FF-FF-FF-FF') -and ((& $getClassValue $_) -ne 'Broadcast')
        })

        $discoveredCountPhrase = if ($broadcastHosts.Count -gt 0) {
            if ($activeDevices.Count -gt 0) {
                "$($activeDevices.Count) perangkat aktif (serta $($broadcastHosts.Count) alamat Broadcast)"
            }
            else {
                "$($broadcastHosts.Count) alamat Broadcast tanpa respons perangkat unicast"
            }
        }
        else {
            "$($activeDevices.Count) host aktif"
        }

        $icmpHosts = @($hostResults | Where-Object { $_.Protocol -eq 'ICMP' })
        $tcpHosts  = @($hostResults | Where-Object { $_.Protocol -like 'TCP*' })

        $tcpPortSummary = if ($tcpHosts.Count -gt 0) {
            $groupedPorts = $tcpHosts | Group-Object -Property Protocol | Sort-Object Count -Descending | ForEach-Object {
                if ($tcpHosts.Count -gt 1) { "$($_.Name) ($($_.Count))" } else { $_.Name }
            }
            $groupedPorts -join ", "
        }
        else {
            ""
        }

        # Susun rincian lapisan protokol (ICMP vs TCP Fallback)
        $protocolDetailText = if ($isSingleTargetScan) {
            $singleItem = $hostResults[0]
            if ($singleItem.Protocol -eq 'ICMP') {
                $ttlNote = if ($singleItem.TTL) { " (TTL: $($singleItem.TTL))" } else { "" }
                "merespons melalui pemeriksaan Layer 3 ICMP$ttlNote"
            }
            else {
                "merespons melalui jalur fallback Layer 4 $($singleItem.Protocol) setelah pemeriksaan ICMP tidak mendapatkan balasan (mengindikasikan adanya penyaringan trafik ping oleh firewall host)"
            }
        }
        else {
            if ($icmpHosts.Count -gt 0 -and $tcpHosts.Count -gt 0) {
                "terdiri atas $($icmpHosts.Count) host yang merespons melalui ICMP dan $($tcpHosts.Count) host melalui fallback $tcpPortSummary (mengindikasikan adanya penyaringan ICMP oleh firewall lokal)"
            }
            elseif ($icmpHosts.Count -gt 0) {
                "seluruhnya merespons normal melalui pemeriksaan Layer 3 ICMP"
            }
            else {
                "seluruhnya terdeteksi melalui jalur fallback Layer 4 $tcpPortSummary karena pemeriksaan Layer 3 ICMP tidak mendapatkan respons"
            }
        }

        # Susun konteks Layer 2 (MAC Address + pengecualian Local Host) jika diaktifkan
        $macContextText = ""
        if ($showMac -and $activeDevices.Count -gt 0) {
            $isLocalSelfClosure = {
                param($h)
                $cls = & $getClassValue $h
                $ipVal = if ($h.PSObject.Properties['IPAddress']) { $h.IPAddress } elseif ($h.PSObject.Properties['IP']) { $h.IP } else { $null }
                return ($cls -like 'Local Host*') -or ($null -ne $ipVal -and ($localIPs -contains $ipVal))
            }

            $unicastMacHosts = @($activeDevices | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.MACAddress) -and
                $_.MACAddress -ne 'N/A' -and
                (($_.MACAddress -replace ':', '-') -ne 'FF-FF-FF-FF-FF-FF')
            })
            $localSelfHosts = @($activeDevices | Where-Object {
                (& $isLocalSelfClosure $_) -and
                ([string]::IsNullOrWhiteSpace($_.MACAddress) -or $_.MACAddress -eq 'N/A')
            })

            if ($isSingleTargetScan) {
                $singleItem = $activeDevices[0]
                $singleMac  = $singleItem.MACAddress
                if (& $isLocalSelfClosure $singleItem) {
                    $macContextText = ", yang merupakan perangkat lokal ini sendiri (Local Host) pada segmen Layer 2"
                }
                elseif (-not [string]::IsNullOrWhiteSpace($singleMac) -and $singleMac -ne 'N/A') {
                    $macContextText = ", dengan alamat MAC $singleMac terdeteksi yang mengonfirmasi host berada dalam segmen Layer 2 lokal yang sama"
                }
                else {
                    $macContextText = ", dengan alamat MAC tidak tercatat di tabel ARP lokal (menandakan akses melewati router/hop Layer 3)"
                }
            }
            else {
                $totalLayer2Local = $unicastMacHosts.Count + $localSelfHosts.Count
                if ($localSelfHosts.Count -gt 0) {
                    if ($totalLayer2Local -eq $activeDevices.Count) {
                        $macContextText = ", dengan seluruh perangkat (termasuk Local Host) terkonfirmasi berada dalam segmen Layer 2 lokal yang sama"
                    }
                    else {
                        $macContextText = ", dengan $totalLayer2Local perangkat (termasuk Local Host) terkonfirmasi berada dalam segmen Layer 2 lokal yang sama"
                    }
                }
                elseif ($unicastMacHosts.Count -eq $activeDevices.Count) {
                    $macContextText = ", dengan seluruh alamat MAC berhasil dipetakan pada segmen broadcast Layer 2 lokal"
                }
                elseif ($unicastMacHosts.Count -gt 0) {
                    $macContextText = ", dengan $($unicastMacHosts.Count) dari $($activeDevices.Count) perangkat terdeteksi alamat MAC-nya dalam segmen Layer 2 lokal"
                }
                else {
                    $macContextText = ", tanpa resolusi alamat MAC lokal karena seluruh target berada di balik rute Layer 3"
                }
            }
        }

        # Susun ringkasan Inferred Classification jika diaktifkan
        $classificationContextText = ""
        if ($runClassification -and $activeDevices.Count -gt 0) {
            $classCounts = @{}
            foreach ($item in $activeDevices) {
                $classVal = & $getClassValue $item
                if (-not [string]::IsNullOrWhiteSpace($classVal) -and $classVal -notin @('Unknown', 'N/A', '-', 'Broadcast')) {
                    if (-not $classCounts.ContainsKey($classVal)) { $classCounts[$classVal] = 0 }
                    $classCounts[$classVal]++
                }
            }

            if ($classCounts.Count -gt 0) {
                if ($isSingleTargetScan) {
                    $singleClass = ($classCounts.Keys | Select-Object -First 1)
                    $classificationContextText = ", dan terklasifikasi sebagai $singleClass"
                }
                else {
                    $classItems = @($classCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
                        "$($_.Value) $($_.Key)"
                    })
                    $classJoined = if ($classItems.Count -eq 1) {
                        $classItems[0]
                    }
                    elseif ($classItems.Count -eq 2) {
                        "$($classItems[0]) dan $($classItems[1])"
                    }
                    else {
                        "$($classItems[0..($classItems.Count - 2)] -join ', '), dan $($classItems[-1])"
                    }
                    $classificationContextText = ", serta komposisi perangkat mencakup $classJoined"
                }
            }
        }

        # Susun rekomendasi tindak lanjut berdasarkan segmen & temuan protokol
        $mitigationActionText = if ($scopeSegmentText -eq "internal") {
            if ($isSingleTargetScan) {
                "sehingga konektivitas dasar menuju host tersebut dinyatakan aktif dan pemeriksaan lanjutan dapat difokuskan pada verifikasi layanan spesifik atau kesesuaian aset internal."
            }
            elseif ($tcpHosts.Count -gt 0) {
                "sehingga disarankan untuk mencocokkan seluruh perangkat aktif dengan inventaris aset resmi (asset baseline) serta memverifikasi kebijakan firewall pada host yang memblokir ICMP."
            }
            else {
                "sehingga disarankan untuk mencocokkan daftar perangkat aktif tersebut dengan inventaris aset resmi guna memastikan tidak terdapat perangkat tidak dikenal pada segmen jaringan."
            }
        }
        elseif ($scopeSegmentText -eq "publik") {
            "sehingga disarankan untuk memverifikasi kelayakan eksposur layanan pada perimeter serta meninjau reputasi alamat IP apabila tidak termasuk dalam daftar aset resmi."
        }
        else {
            "sehingga disarankan untuk memverifikasi daftar host internal terhadap inventaris aset resmi sekaligus mengaudit eksposur layanan pada target publik yang terdeteksi aktif."
        }

        if ($isSingleTargetScan) {
            $conclusionParagraph = "Pemindaian terhadap $targetDescriptor mengonfirmasi bahwa host dalam status aktif dan $protocolDetailText$macContextText$classificationContextText, $mitigationActionText"
        }
        else {
            $conclusionParagraph = "Pemindaian terhadap $targetDescriptor berhasil menemukan $discoveredCountPhrase dari $totalScannedCount alamat yang diperiksa, $protocolDetailText$macContextText$classificationContextText, $mitigationActionText"
        }
    }

    Write-Host "`n[*] Conclusion: $conclusionParagraph" @Cha
}
