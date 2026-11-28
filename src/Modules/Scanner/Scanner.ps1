. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'ScannerApplication.ps1'))"

function scanner {
    param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    function scannerTransport {
        if ($targets[0] -eq "") {
            Write-Host "You must specify at least one target with -targets.`nExiting now." @Pen
            return
        }

        $garudaDataDir = [System.IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'), 'Garuda')
        $PortListPath = [System.IO.Path]::Combine($garudaDataDir, 'ports.txt')

        . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'PopulatePortsHash.ps1')))"
        . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'UpdatePortDatabase.ps1')))"

        $portsHashTable = updatePortDatabase

        $result = [System.Collections.Concurrent.ConcurrentDictionary[object, object]]::new() 

        foreach ($target in $targets) {
            try {
                $resolvedIP = [System.Net.Dns]::GetHostAddresses($target)[0]
                $TargetIP = $resolvedIP.IPAddressToString
                $TargetFamily = $resolvedIP.AddressFamily
            } catch {
                Write-Warning "Failed to find IP for host: $target. Skipping this target..."
                continue
            }

            . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'PortToScan.ps1')))"
            
            $portsToScan = portToScan -QuickScan:$quickScan -Ports $ports -PMin $pMin -PMax $pMax
            $totalPorts = $portsToScan.Count

            if ($totalPorts -gt 0) {
                0..($totalPorts - 1) | ForEach-Object -Parallel {
                    $index = $_
                    $portsToScan = $using:portsToScan
                    $port = $portsToScan[$index]
                    
                    $Target = $using:target
                    $TargetIP = $using:TargetIP
                    $TargetFamily = $using:TargetFamily
                    $portsHashTable = $using:portsHashTable
                    $portInt = [Int]$port
                    $localResult = $using:result
                    $totalPorts = $using:totalPorts

                    $completed = (($index + 1) / $totalPorts) * 100
                    Write-Progress -Activity "Scanning ${Target}:$port" -Status "$([math]::Round($completed, 2))% complete" -PercentComplete $completed

                    $obj = [System.Net.Sockets.Socket]::new(
                        $TargetFamily, 
                        [System.Net.Sockets.SocketType]::Stream, 
                        [System.Net.Sockets.ProtocolType]::Tcp
                    )

                    $obj.NoDelay = $true
                    $obj.SendTimeout = ($TargetIP -match '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.') ? 100 : 500
                    $obj.ReceiveTimeout = $obj.SendTimeout

                    $ip = [System.Net.IPAddress]::Parse($TargetIP)
                    $endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                    
                    try {
                        $connect = $obj.BeginConnect($endpoint, $null, $null)
                        $Wait = $connect.AsyncWaitHandle.WaitOne($obj.SendTimeout, $false)

                        if (-not $Wait) {
                            Write-Verbose -Message "$Target 'port' $port 'Closed - Timeout'" -Verbose
                        }
                        else {
                            if ($obj.Connected) {
                                $obj.EndConnect($connect)

                                $value = "Open"
                                Write-Verbose -Message "$Target 'port' $port Open'" -Verbose

                                if ($portsHashTable.ContainsKey($portInt)) {
                                    $Service = $portsHashTable[$portInt].Split('|')
                                }
                                else {
                                    $Service = @("Unknown", "Unknown")
                                }

                                $r = [PSCustomObject]@{
                                    Host = $Target
                                    Port = $port
                                    State = $value
                                    L4_Service = $Service[0]
                                    "IANA Standard Description" = $Service[1]
                                }

                                $key = $Target + ":" + $port
                                $localResult[$key] = $r
                            }
                            else {
                                Write-Verbose -Message "$Target 'port' $port 'Closed - Refused'" -Verbose
                            }
                        }
                    } catch {
                        Write-Verbose -Message "$Target 'port' $port 'Error: $($_.Exception.Message)'" -Verbose
                    } finally {
                        $obj.Close()
                        $obj.Dispose()
                    }
                } @ThrottleCreat
            }
        }

        Write-Host "`n[+] Layer 4 Scan Results:" @App
        
        $result.Values | ForEach-Object {
            $dto = [HostResult]::new($_.Host)
            $dto.Port = $_.Port
            $dto.State = $_.State
            $dto.Service = $_.L4_Service
            $dto.IANADescription = $_."IANA Standard Description"
            $dto
        } | Sort-Object IPAddress, Port | Select-Object IPAddress, Port, State, Service, IANADescription | Format-Table -AutoSize

        $phase1Data = $result.Values | Sort-Object host, port 
        $openPorts = $phase1Data | Where-Object { $_.State -eq "Open" }

        if ($openPorts.Count -gt 0) {
            Write-Host ""
            $answer = Read-Host "There are $($openPorts.Count) open ports. Proceed with Layer 7 validation? (y/n)"
            if ($answer -match "^y") {
                scannerApplication -OpenPorts $openPorts
            } else {
                Write-Host "Scanning stopped at Layer 4."
            }
        } else {
            Write-Host "`nNo open ports were found for Layer 7 validation." @Cha
            Write-Host "[*] Possible reasons for empty results:" @Dim
            Write-Host " 1. Target Firewall/WAF/IPS packet drop." @Dim
            Write-Host " 2. Network latency exceeded timeout limit." @Dim
            Write-Host " 3. Local gateway NAT buffer overflow." @Dim
            Write-Host " 4. Outbound traffic rate-limited by ISP." @Dim
            Write-Host " 5. Local socket or thread exhaustion." @Dim
        }

        # ==========================================================
        # Konklusi Dinamis Satu Paragraf (Port & Service Scan Summary)
        # ==========================================================
        $cleanTargets = @($targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $internalPattern = '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)'

        $internalCount = 0
        $publicCount   = 0
        foreach ($t in $cleanTargets) {
            $checkAddr = $t
            try {
                $dnsAddr = [System.Net.Dns]::GetHostAddresses($t) | Select-Object -First 1
                if ($null -ne $dnsAddr) { $checkAddr = $dnsAddr.IPAddressToString }
            } catch {}

            if ($checkAddr -match $internalPattern) { $internalCount++ } else { $publicCount++ }
        }

        $scopeSegmentText = if ($internalCount -gt 0 -and $publicCount -eq 0) {
            "internal"
        }
        elseif ($publicCount -gt 0 -and $internalCount -eq 0) {
            "publik"
        }
        else {
            "campuran (internal dan publik)"
        }

        $targetDescriptor = if ($cleanTargets.Count -eq 1) {
            $singleT = $cleanTargets[0]
            if ($TargetIP -and $TargetIP -ne $singleT) {
                "target $scopeSegmentText $singleT ($TargetIP)"
            }
            else {
                "target $scopeSegmentText $singleT"
            }
        }
        else {
            "$($cleanTargets.Count) target $scopeSegmentText ($($cleanTargets -join ', '))"
        }

        $cleanPorts       = @($ports | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hasRange         = ($pMin -gt 0 -or $pMax -gt 0)
        $hasSpecificPorts = ($cleanPorts.Count -gt 0)

        $scanScopeText = if ($hasRange -and $hasSpecificPorts) {
            "pada rentang port $pMin-$pMax serta $($cleanPorts.Count) port spesifik ($($cleanPorts -join ', '))"
        }
        elseif ($hasRange) {
            "pada rentang port $pMin-$pMax"
        }
        elseif ($hasSpecificPorts) {
            "pada $($cleanPorts.Count) port spesifik ($($cleanPorts -join ', '))"
        }
        elseif ($quickScan) {
            "pada daftar port utama (Quick Scan)"
        }
        elseif ($totalPorts -gt 0) {
            "pada $totalPorts port terdaftar"
        }
        else {
            "pada cakupan port yang dikonfigurasi"
        }

        $openPortList = @($openPorts)
        if ($openPortList.Count -eq 0) {
            $mitigationZeroOpen = if ($scopeSegmentText -eq "internal") {
                "sehingga validasi Layer 7 tidak diperlukan dan host kemungkinan dalam kondisi tidak aktif, tidak menjalankan layanan TCP pada port uji, atau terlindungi aturan firewall lokal."
            }
            else {
                "sehingga validasi Layer 7 tidak diperlukan dan host kemungkinan dilindungi kebijakan firewall perimeter yang menyaring koneksi masuk atau sedang tidak aktif pada port yang diuji."
            }

            $conclusionParagraph = "Pemindaian Layer 4 terhadap $targetDescriptor $scanScopeText tidak menemukan satu pun port TCP yang berstatus terbuka (seluruh koneksi timeout atau ditolak), $mitigationZeroOpen"
        }
        else {
            $layer7Executed = ($answer -match "^y")
            $layer7StatusText = if ($layer7Executed) {
                "dengan validasi lanjutan Layer 7 telah dijalankan untuk memverifikasi respons layanan aplikasi aktif"
            }
            else {
                "sementara validasi lanjutan Layer 7 tidak dijalankan sehingga identifikasi layanan masih berbasis pemetaan port IANA Layer 4"
            }

            # Format daftar port terbuka
            $formattedOpenItems = @()
            if ($cleanTargets.Count -eq 1) {
                $sortedSinglePorts = $openPortList | Sort-Object { [int]$_.Port }
                $formattedOpenItems = @($sortedSinglePorts | ForEach-Object {
                    $svcName = if (-not [string]::IsNullOrWhiteSpace($_.L4_Service) -and $_.L4_Service -ne 'Unknown') { $_.L4_Service } else { "Unknown" }
                    "$($_.Port) ($svcName)"
                })
            }
            else {
                $groupedByHost = $openPortList | Group-Object -Property Host
                $formattedOpenItems = @($groupedByHost | ForEach-Object {
                    $hName = $_.Name
                    $hPorts = ($_.Group | Sort-Object { [int]$_.Port } | ForEach-Object {
                        $svcName = if (-not [string]::IsNullOrWhiteSpace($_.L4_Service) -and $_.L4_Service -ne 'Unknown') { $_.L4_Service } else { "Unknown" }
                        "$($_.Port)/$svcName"
                    }) -join ", "
                    "$hName [$hPorts]"
                })
            }

            $maxDisplayItems = 8
            $portsSummaryText = if ($formattedOpenItems.Count -le $maxDisplayItems) {
                if ($formattedOpenItems.Count -eq 1) {
                    $formattedOpenItems[0]
                }
                elseif ($formattedOpenItems.Count -eq 2) {
                    "$($formattedOpenItems[0]) dan $($formattedOpenItems[1])"
                }
                else {
                    "$($formattedOpenItems[0..($formattedOpenItems.Count - 2)] -join ', '), dan $($formattedOpenItems[-1])"
                }
            }
            else {
                $shownSubset = $formattedOpenItems[0..($maxDisplayItems - 1)] -join ', '
                $remainingCount = $formattedOpenItems.Count - $maxDisplayItems
                "$shownSubset, serta $remainingCount port terbuka lainnya"
            }

            # Klasifikasi risiko port terbuka
            $sensitivePortNums = @(21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 27017)
            $exposedSensitive  = @($openPortList | Where-Object { [int]$_.Port -in $sensitivePortNums })
            $unknownServices   = @($openPortList | Where-Object { [string]::IsNullOrWhiteSpace($_.L4_Service) -or $_.L4_Service -eq 'Unknown' })

            $mitigationOpenText = if ($exposedSensitive.Count -gt 0) {
                $sensList = ($exposedSensitive | Sort-Object { [int]$_.Port } | ForEach-Object { "$($_.Port) ($($_.L4_Service))" } | Select-Object -Unique) -join ", "
                if ($scopeSegmentText -eq "internal") {
                    "sehingga teridentifikasi eksposur layanan administrasi, berbagi berkas, atau basis data pada segmen internal ($sensList) yang perlu dipastikan pembatasan aksesnya sesuai kebijakan segmentasi jaringan."
                }
                else {
                    "sehingga teridentifikasi eksposur layanan sensitif pada perimeter publik ($sensList) yang disarankan untuk segera dibatasi melalui firewall/IP whitelisting apabila tidak ditujukan untuk akses eksternal."
                }
            }
            elseif ($unknownServices.Count -gt 0 -and -not $layer7Executed) {
                "sehingga disarankan untuk menjalankan pemeriksaan banner atau inspeksi Layer 7 guna memastikan identitas layanan non-standar (Unknown) yang aktif serta kesesuaiannya dengan inventaris aset resmi."
            }
            else {
                if ($scopeSegmentText -eq "internal") {
                    "sehingga disarankan untuk mencocokkan layanan aktif tersebut dengan daftar layanan yang diizinkan pada host internal guna memastikan tidak ada servis tidak sah yang berjalan."
                }
                else {
                    "sehingga disarankan untuk memverifikasi kelayakan eksposur layanan tersebut pada perimeter publik serta memastikan konfigurasi keamanan aplikasinya telah diperkeras."
                }
            }

            $conclusionParagraph = "Pemindaian Layer 4 terhadap $targetDescriptor $scanScopeText menemukan $($openPortList.Count) port terbuka, yaitu $portsSummaryText, $layer7StatusText, $mitigationOpenText"
        }

        Write-Host "`n[*] Conclusion: $conclusionParagraph" @Cha
    }

    scannerTransport
}
