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
    }

    scannerTransport
}
