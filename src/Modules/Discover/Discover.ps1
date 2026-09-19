. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'InternetProtocolRange.ps1'))"

function discover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

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
                }
                catch {
                    $isReachable = $false 
                }
                finally {
                    $pingSender.Dispose()
                }

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
                        }
                        catch {}
                        finally {
                            $tcpClient.Close()
                            $tcpClient.Dispose()
                        }
                    }
                }

                $localResult[$ip] = $method

                if ($method -eq "None") {
                    Write-Verbose "$ip is not reachable"
                }
            } @ThrottleCreat

            $reachableCount = 0
            $showMac = $false
            $runClassification = $false

            if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                $hasReachable = $false

                foreach ($ip in $ipRange) { 
                    if ($reachableTargets.ContainsKey($ip) -and $reachableTargets[$ip] -ne "None") { 
                        $hasReachable = $true
                        break 
                    } 
                }
                
                if ($hasReachable) {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    $ask = Read-Host " [*] Show MAC Address? (Y/N)"
                    if ($ask -match '^[Yy]') { $showMac = $true }

                    $askClass = Read-Host " [*] Discover Switch & Router / Device OS? (Y/N)"
                    if ($askClass -match '^[Yy]') { $runClassification = $true }
                }
            }

            Write-Host ""
            $headerIP = "IP Address".PadRight(16)
            $headerProto = "Protocol".PadRight(14)
            $headerMac = if ($showMac -or $runClassification) { "MAC Address".PadRight(20) } else { "" }
            $headerClass = if ($runClassification) { "Classification" } else { "" }
            
            $headerStr = "$headerIP $headerProto $headerMac $headerClass".TrimEnd()
            Write-Host " $headerStr" @App
            Write-Host " $("-" * $headerStr.Length)" @Dim

            foreach ($ip in $ipRange | Sort-Object) {
                $detectedMethod = $reachableTargets[$ip]
                
                if ($detectedMethod -ne "None") {
                    $mac = "N/A"

                    if ($showMac -or $runClassification) {
                        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                            $mac = (Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                            if (-not $mac) { $mac = "N/A" }
                        } else {
                            $mac = "N/A (OS Not Supported)"
                        }
                    }
                    
                    if ($detectedMethod -match 'ICMP \(TTL:(\d+)\)') {
                        $ttl = [int]$matches[1]
                        $protoDisplay = "ICMP ($ttl)"
                        if (-not $runClassification) { $protoDisplay = "ICMP" }
                    } else {
                        $ttl = 0
                        $protoDisplay = $detectedMethod
                    }

                    $deviceLabel = ""
                    if ($runClassification) {
                        $deviceLabel = "Unknown Host"
                        
                        if ($ttl -gt 128 -and $ttl -le 255) {
                            $deviceLabel = "Network Appliance / Cisco (Base: 255)"
                        } elseif ($ttl -gt 64 -and $ttl -le 128) {
                            $deviceLabel = "Windows OS (Base: 128)"
                        } elseif ($ttl -gt 0 -and $ttl -le 64) {
                            $deviceLabel = "Linux/macOS / NGFW (Base: 64)"
                        }

                        if ($ip -match '\.(1|254)$' -and $ttl -gt 128) {
                            $deviceLabel = "Core Switch / Router Gateway"
                        }
                        if ($mac -eq 'FF-FF-FF-FF-FF-FF') {
                            $deviceLabel = "Subnet Broadcast"
                        }
                        if ($ttl -eq 0 -and $detectedMethod -match 'TCP') {
                            $deviceLabel = "Filtered / Silent Host"
                        }
                    }
                    
                    $colIP = $ip.PadRight(16)
                    $colProto = $protoDisplay.PadRight(14)
                    $colMac = if ($showMac -or $runClassification) { $mac.PadRight(20) } else { "" }
                    
                    $rowStr = "$colIP $colProto $colMac $deviceLabel".TrimEnd()
                    Write-Host " $rowStr" @App

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
            }
            catch { }
            finally { $pingSingle.Dispose() }
            
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
                    }
                    catch {}
                    finally {
                        $tcpClientSingle.Close()
                        $tcpClientSingle.Dispose()
                    }
                }
            }

            if ($method -ne "None") {
                $showMacSingle = $false
                $runClassSingle = $false
                $mac = "N/A"

                if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    
                    $ask = Read-Host " [*] Show MAC Address? (Y/N)"
                    if ($ask -match '^[Yy]') { $showMacSingle = $true }
                    
                    $askClass = Read-Host " [*] Discover Switch & Router / Device OS? (Y/N)"
                    if ($askClass -match '^[Yy]') { $runClassSingle = $true }

                    if ($showMacSingle -or $runClassSingle) { 
                        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                            $mac = (Get-NetNeighbor -IPAddress $target -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                            if (-not $mac) { $mac = "N/A" }
                        } else {
                            $mac = "N/A (OS Not Supported)"
                        }
                    }
                }

                $macOutput = if ($showMacSingle) { " [MAC: $mac]" } else { "" }

                $classOutput = ""
                
                if ($method -match 'ICMP \(TTL:(\d+)\)') {
                    $ttl = [int]$matches[1]
                    $displayMethod = "ICMP ($ttl)"

                    if (-not $runClassSingle) {
                        $displayMethod = "ICMP"
                    }
                } else {
                    $ttl = 0
                    $displayMethod = $method
                }

                if ($runClassSingle) {
                    $deviceLabel = "Unknown Host"
                    if ($ttl -gt 128 -and $ttl -le 255) {
                        $deviceLabel = "Network Appliance / Cisco (Base: 255)"
                    } elseif ($ttl -gt 64 -and $ttl -le 128) {
                        $deviceLabel = "Windows OS (Base: 128)"
                    } elseif ($ttl -gt 0 -and $ttl -le 64) {
                        $deviceLabel = "Linux/macOS / NGFW (Base: 64)"
                    }

                    if ($target -match '\.(1|254)$' -and $ttl -gt 128) {
                        $deviceLabel = "Core Switch / Router Gateway"
                    }
                    if ($mac -eq 'FF-FF-FF-FF-FF-FF') {
                        $deviceLabel = "Subnet Broadcast"
                    }
                    if ($ttl -eq 0 -and $method -match 'TCP') {
                        $deviceLabel = "Filtered / Silent Host"
                    }
                }

                Write-Host ""
                $headerIP = "IP Address".PadRight(16)
                $headerProto = "Protocol".PadRight(14)
                $headerMac = if ($showMacSingle -or $runClassSingle) { "MAC Address".PadRight(20) } else { "" }
                $headerClass = if ($runClassSingle) { "Classification" } else { "" }
                
                $headerStr = "$headerIP $headerProto $headerMac $headerClass".TrimEnd()
                Write-Host " $headerStr" @App
                Write-Host " $("-" * $headerStr.Length)" @Dim

                $colIP = $target.PadRight(16)
                $colProto = $displayMethod.PadRight(14)
                $colMac = if ($showMacSingle -or $runClassSingle) { $mac.PadRight(20) } else { "" }
                $finalLabel = if ($runClassSingle) { $deviceLabel } else { "" }

                $rowStr = "$colIP $colProto $colMac $finalLabel".TrimEnd()
                Write-Host " $rowStr" @App

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
}
