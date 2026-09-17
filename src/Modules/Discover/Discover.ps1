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
                            $method = "ICMP"
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
                }
            }

            foreach ($ip in $ipRange | Sort-Object) {
                $detectedMethod = $reachableTargets[$ip]
                
                if ($detectedMethod -ne "None") {
                    $macOutput = ""
                    if ($showMac) {
                        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                            $mac = (Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                            if (-not $mac) { $mac = "N/A" }
                        } else {
                            $mac = "N/A (OS Not Supported)"
                        }
                        $macOutput = " [MAC: $mac]"
                    }
                    
                    Write-Host "$ip is reachable via $detectedMethod$macOutput" @App
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
                        $method = "ICMP"
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
                            # <--- PERUBAHAN 2: Menutup siklus Async untuk Single Target --->
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
                if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    $ask = Read-Host " [*] Show MAC Address? (Y/N)"
                    if ($ask -match '^[Yy]') { 
                        $showMacSingle = $true 
                        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
                            $mac = (Get-NetNeighbor -IPAddress $target -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                            if (-not $mac) { $mac = "N/A" }
                        } else {
                            $mac = "N/A (OS Not Supported)"
                        }
                    }
                }

                $macOutput = if ($showMacSingle) { " [MAC: $mac]" } else { "" }
                Write-Host "$target is reachable via $method$macOutput" @App
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
