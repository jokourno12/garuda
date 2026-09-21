. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'InternetProtocolRange.ps1'))"

function discover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    $localIPs = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress

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
                            $ttl = $reply.Options.Ttl
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
                        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                            $macResult = (Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                            $dto.MACAddress = if ($macResult) { $macResult } else { "N/A" }
                        } else {
                            $dto.MACAddress = "N/A (OS Not Supported)"
                        }
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
                        $ttl = $reply.Options.Ttl
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
                    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                        $macResult = (Get-NetNeighbor -IPAddress $target -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                        $dto.MACAddress = if ($macResult) { $macResult } else { "N/A" }
                    } else {
                        $dto.MACAddress = "N/A (OS Not Supported)"
                    }
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
}