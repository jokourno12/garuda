function scannerApplication {
    param(
        [Parameter(Mandatory=$true)]
        [array]$OpenPorts
    )

    $denoCmd =$null
    if (Get-Command deno -ErrorAction SilentlyContinue) {
        $denoCmd = "deno"
    } elseif (Test-Path "$HOME/.deno/bin/deno") {
        $denoCmd = "$HOME/.deno/bin/deno"
    }

    if ($null -ne$denoCmd) {
        Write-Host "`n[+] Deno engine detected. Using Deno for Layer 7 optimization..." @Net
        
        $scriptPath = [System.IO.Path]::Combine($PSScriptRoot, 'Private', 'ScannerApplication.js')
        $tempFile = [System.IO.Path]::GetTempFileName()
        
        try {
            ConvertTo-Json -InputObject @($OpenPorts) -Depth 10 -Compress | Out-File -FilePath $tempFile -Encoding utf8
            
            $denoOutput = (& $denoCmd run --quiet --allow-net --allow-read $scriptPath $tempFile) -join ""
            
            if (-not [string]::IsNullOrWhiteSpace($denoOutput)) {
                $l7Output = @($denoOutput | ConvertFrom-Json)
                
                if ($null -ne $l7Output -and $l7Output.Count -gt 0) {
                    $l7Output | ForEach-Object {
                        $dto = [HostResult]::new($_.Host)
                        $dto.Port = $_.Port
                        $dto.Service = $_.L4_Service
                        $dto.L7Banner = $_.L7_Banner
                        $dto
                    } | Sort-Object IPAddress, Port | Select-Object IPAddress, Port, Service, L7Banner | Format-Table -AutoSize
                } else {
                    Write-Host "`nNo service returns a banner at Layer 7 (Deno Engine)." @Cha
                }
            } else {
                Write-Host "`nNo service returns a banner at Layer 7 (Deno Engine)." @Cha
            }
        } catch {
            Write-Host "`n[!] Deno execution failed. Error: $($_.Exception.Message)" @Pen
        } finally {
            if (Test-Path $tempFile) { Remove-Item -Path$tempFile -Force }
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
                        $sslTask = $sslStream.AuthenticateAsClientAsync($target)
                        if ($sslTask.Wait(1500)) {
                            $activeStream = $sslStream
                        } else {
                            throw "SSL Handshake Timeout"
                        }
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
                L4_Service = $item.L4_Service
                L7_Banner = $banner
            }
            $localResult = $using:l7Result
            $localResult[$key] = $r
        } @ThrottleCreat

        $validL7 = $l7Result.Values | Where-Object { $_.L7_Banner -ne "No Banner / Timeout" }

        if ($validL7.Count -gt 0) {
            $validL7 | ForEach-Object {
                $dto = [HostResult]::new($_.Host)
                $dto.Port = $_.Port
                $dto.Service = $_.L4_Service
                $dto.L7Banner = $_.L7_Banner
                $dto
            } | Sort-Object IPAddress, Port | Select-Object IPAddress, Port, Service, L7Banner | Format-Table -AutoSize
        } else {
            Write-Host "`nNo service returns a banner at Layer 7." @Cha
        }
    }
}