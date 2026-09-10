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

            foreach ($ip in $ipRange | Sort-Object) {

                if ($reachableTargets[$ip]) {
                    Write-Host "$ip is reachable" @App
                }
                else {
                    Write-Verbose "$ip is not reachable"
                }
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
                Write-Host "$target is reachable" @App
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
