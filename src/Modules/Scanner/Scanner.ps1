. "$([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Runtime', 'Windows.ps1'))"

function scanner {
    param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    # FASE 2: VALIDASI LAYER 7 (APPLICATION)
    function scannerApplication {
        param(
            [Parameter(Mandatory=$true)]
            [array]$OpenPorts
        )

        $denoCmd = Get-Command deno -ErrorAction SilentlyContinue

        if ($null -ne $denoCmd) {
            Write-Host "`n[+] Deno engine detected. Using Deno for Layer 7 optimization..." @Net
            
            $scriptPath = [System.IO.Path]::Combine($PSScriptRoot, 'Private', 'ScannerApplication.js')
            
            # Menggunakan Temporary File untuk menjembatani data (Mencegah Deadlock Stdin)
            $tempFile = [System.IO.Path]::GetTempFileName()
            
            try {
                $OpenPorts | ConvertTo-Json -Compress | Out-File -FilePath $tempFile -Encoding utf8
                
                # Eksekusi Deno dengan akses baca ke temp file
                $denoOutput = & deno run --allow-net --allow-read $scriptPath $tempFile
                
                if (-not [string]::IsNullOrWhiteSpace($denoOutput)) {
                    $l7Output = $denoOutput | ConvertFrom-Json
                    
                    if ($null -ne $l7Output -and $l7Output.Count -gt 0) {
                        $l7Output | Sort-Object Host, Port | Format-Table -AutoSize
                    } else {
                        Write-Host "`nNo service returns a banner at Layer 7 (Deno Engine)." @Cha
                    }
                } else {
                    Write-Host "`nNo service returns a banner at Layer 7 (Deno Engine)." @Cha
                }
            } catch {
                Write-Host "`n[!] Deno execution failed. Error: $($_.Exception.Message)" @Pen
            } finally {
                if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force }
            }
        } else {
            Write-Host "`n[!] Deno engine not found. Install Deno for Layer 7 optimization." @Cha
            Write-Host "Starting native PowerShell Layer 7 scanning on $($OpenPorts.Count) open port..." @Net

            $l7Result = [System.Collections.Concurrent.ConcurrentDictionary[object, object]]::new()

            $OpenPorts | ForEach-Object -Parallel {
                $item = $_
                $target = $item.Host
                $port = $item.Port
                $key = $target + ":" + $port
                
                $banner = "No Banner / Timeout"

                try {
                    $tcpClient = [System.Net.Sockets.TcpClient]::new()
                    $connect = $tcpClient.BeginConnect($target, $port, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne(1000, $false)

                    if ($wait -and $tcpClient.Connected) {
                        $tcpClient.EndConnect($connect)
                        
                        $stream = $tcpClient.GetStream()
                        $stream.ReadTimeout = 2000 
                        $stream.WriteTimeout = 2000
                        
                        $activeStream = $stream

                        if ($port -in 443, 8443) {
                            $sslStream = [System.Net.Security.SslStream]::new($stream)
                            $sslStream.AuthenticateAsClient($target)
                            $activeStream = $sslStream
                        }

                        if ($port -in 80, 8080, 443, 8443) {
                            $writer = [System.IO.StreamWriter]::new($activeStream)
                            $writer.WriteLine("HEAD / HTTP/1.1")
                            $writer.WriteLine("Host: $target")
                            $writer.WriteLine("Connection: close")
                            $writer.WriteLine("")
                            $writer.Flush()
                        }

                        $reader = [System.IO.StreamReader]::new($activeStream)
                        $readTask = $reader.ReadLineAsync()
                        
                        if ($readTask.Wait(2000)) {
                            $bannerData = $readTask.Result
                            if (-not [string]::IsNullOrWhiteSpace($bannerData)) {
                                $banner = $bannerData.Trim()
                            }
                        }
                    }
                } catch {
                    $banner = "Error: $($_.Exception.Message)"
                } finally {
                    if ($null -ne $tcpClient) {
                        $tcpClient.Close()
                        $tcpClient.Dispose()
                    }
                }

                $r = [PSCustomObject]@{
                    Host = $target
                    Port = $port
                    L4_Service = $item.Service
                    L7_Banner = $banner
                }
                $localResult = $using:l7Result
                $localResult[$key] = $r
            } -ThrottleLimit 15

            $validL7 = $l7Result.Values | Where-Object { $_.L7_Banner -ne "No Banner / Timeout" }

            if ($validL7.Count -gt 0) {
                $validL7 | Sort-Object Host, Port | Format-Table -AutoSize
            } else {
                Write-Host "`nNo service returns a banner at Layer 7." @Cha
            }
        }
    }


    # FASE 1: DISCOVERY LAYER 4 (TRANSPORT)
    function scannerTransport {
        if ($targets[0] -eq "") {
            Write-Host "You must specify at least one target with -targets.`nExiting now." @Pen
            return
        }

        $PortListPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Support', 'ports.txt')

        . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'populatePortsHash.ps1')))"
        . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'updatePortDatabase.ps1')))"

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

            . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'portToScan.ps1')))"
            
            $portsToScan = portToScan
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
                    $portInt = [Int] $port
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
                    $obj.SendTimeout = 100
                    $obj.ReceiveTimeout = 100

                    $ip = [System.Net.IPAddress]::Parse($TargetIP)
                    $endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                    
                    try {
                        $connect = $obj.BeginConnect($endpoint, $null, $null)
                        $Wait = $connect.AsyncWaitHandle.WaitOne(100, $false)

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
                                    Service = $Service[0]
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
                } -ThrottleLimit 15
            }
        }

        Write-Host "`n[+] Layer 4 Scan Results:" @App
        $phase1Data = $result.Values | Sort-Object host, port 
        $phase1Data | Format-Table -AutoSize

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
        }
    }

    # =========================================================================
    # EKSEKUSI ORCHESTRATOR
    # Memulai rantai eksekusi dengan memanggil Layer 4
    # =========================================================================
    scannerTransport
}