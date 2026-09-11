. "$([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Runtime', 'Windows.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'InternetProtocolRange.ps1'))"

function discover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    $reachableTargets = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()

    foreach ($target in $targets) {
        if ($target -match "/") {

            $ipRange = internetProtocolRange -subnet $target

            $ipRange | ForEach-Object -Parallel {
                $ip = $_
                $localResult = $using:reachableTargets

                Write-Progress -Activity "Checking if $ip is reachable"

                $isReachable = $false
                $pingSender = [System.Net.NetworkInformation.Ping]::new()
                
                try {
                    for ($i = 0; $i -lt 2; $i++) {
                        $reply = $pingSender.Send($ip, 1000)
                        
                        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                            $isReachable = $true
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

                # --- INJEKSI LOGIKA LAYER 4 (TCP FALLBACK) ---
                if (-not $isReachable) {
                    foreach ($port in @(443, 80)) {
                        if ($isReachable) { break }
                        $tcpClient = [System.Net.Sockets.TcpClient]::new()
                        try {
                            $connectResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
                            $success = $connectResult.AsyncWaitHandle.WaitOne(1000, $true)
                            if ($success -and $tcpClient.Connected) {
                                $isReachable = $true
                            }
                        }
                        catch {}
                        finally {
                            $tcpClient.Close()
                            $tcpClient.Dispose()
                        }
                    }
                }
                # ---------------------------------------------

                if ($isReachable) {
                    $localResult[$ip] = $true
                }
                else {
                    $localResult[$ip] = $false
                    Write-Verbose "$ip is not reachable"
                }
            } -ThrottleLimit 15

            $reachableCount = 0

            # --- INJEKSI LOGIKA MAC ADDRESS (SUBNET) ---
            $showMac = $false
            # Cek apakah target adalah IP Privat (10.x, 172.16-31.x, 192.168.x)
            if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                # Pastikan ada minimal 1 IP yang reachable agar tidak bertanya sia-sia
                $hasReachable = $false
                foreach ($key in $reachableTargets.Keys) { if ($reachableTargets[$key]) { $hasReachable = $true; break } }
                
                if ($hasReachable) {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    $ask = Read-Host " [*] Show MAC Address? (Y/N)"
                    if ($ask -match '^[Yy]') { $showMac = $true }
                }
            }
            # -------------------------------------------

            foreach ($ip in $ipRange | Sort-Object) {

                if ($reachableTargets[$ip]) {
                    # --- INJEKSI OUTPUT MAC ---
                    if ($showMac) {
                        $mac = (Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                        if (-not $mac) { $mac = "N/A" }
                        Write-Host "$ip is reachable [MAC: $mac]" @App
                    }
                    else {
                        Write-Host "$ip is reachable" @App
                    }
                    # --------------------------
                    $reachableCount++
                }
                else {
                    Write-Verbose "$ip is not reachable"
                }
            }

            if ($reachableCount -eq 0) {
                Write-Host " [*] Layer 3 ICMP Checked." @Dim
                Write-Host " [*] Layer 4 TCP Checked." @Dim
                Write-Host " [*] All IPs in subnet $target are not reachable." @Cha
            }

        }
        else {

            $isReachableSingle = $false
            $pingSingle = [System.Net.NetworkInformation.Ping]::new()
            
            try {
                for ($i = 0; $i -lt 2; $i++) {
                    $reply = $pingSingle.Send($target, 1000)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $isReachableSingle = $true
                        break
                    }
                }
            }
            catch { $isReachableSingle = $false }
            finally { $pingSingle.Dispose() }
            
            # --- INJEKSI LOGIKA LAYER 4 (TCP FALLBACK) ---
            $method = "ICMP"
            if (-not $isReachableSingle) {
                # Memberikan informasi bahwa ICMP gagal dan lanjut ke Layer 4
                Write-Host " [*] Layer ICMP possible blocked for $target." @Cha
                Write-Host " [*] Attempting Layer 4 (TCP)..." @Inc

                foreach ($port in @(443, 80)) {
                    if ($isReachableSingle) { break }
                    $tcpClientSingle = [System.Net.Sockets.TcpClient]::new()
                    try {
                        $connectResult = $tcpClientSingle.BeginConnect($target, $port, $null, $null)
                        $success = $connectResult.AsyncWaitHandle.WaitOne(1000, $true)
                        if ($success -and $tcpClientSingle.Connected) {
                            $isReachableSingle = $true
                            $method = "TCP/$port" # Mencatat port yang berhasil
                        }
                    }
                    catch {}
                    finally {
                        $tcpClientSingle.Close()
                        $tcpClientSingle.Dispose()
                    }
                }
            }
            # ---------------------------------------------

            if ($isReachableSingle) {
                # --- INJEKSI LOGIKA MAC ADDRESS (SINGLE TARGET) ---
                $showMacSingle = $false
                if ($target -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
                    Write-Host " [*] Internal IP Detected ($target)." @Cha
                    $ask = Read-Host " [*] Show MAC Address? (Y/N)"
                    if ($ask -match '^[Yy]') { 
                        $showMacSingle = $true 
                        $mac = (Get-NetNeighbor -IPAddress $target -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress
                        if (-not $mac) { $mac = "N/A" }
                    }
                }

                if ($showMacSingle) {
                    Write-Host "$target is reachable [MAC: $mac]" @App
                } else {
                    Write-Host "$target is reachable" @App
                }
                # --------------------------------------------------
                $reachableTargets[$target] = $true 
            }
            else {
                Write-Host "$target is not reachable" @Cha
            }
        }
    }

    if ($VerbosePreference -ne 'SilentlyContinue') {

        Write-Host "`nReachable Hosts:" @Net

        foreach ($ip in $reachableTargets.Keys | Sort-Object) {
            if ($reachableTargets[$ip]) {
                Write-Host " - $ip"
            }
        }
    }
}
