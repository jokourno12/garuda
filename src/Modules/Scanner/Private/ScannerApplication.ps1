function scannerApplication {
    param(
        [Parameter(Mandatory=$true)]
        [array]$OpenPorts
    )

    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    $isWin = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    $llrtBinaryName = if ($isWin -and $arch -eq 'X64') {
        'llrt-windows-x64-no-sdk.exe'
    } elseif ($IsLinux -and $arch -eq 'X64') {
        'llrt-linux-x64-no-sdk'
    } elseif ($IsMacOS -and $arch -eq 'Arm64') {
        'llrt-darwin-arm64-no-sdk'
    } else {
        $null
    }

    $llrtCmd = $null
    if ($null -ne $llrtBinaryName) {
        $searchDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
        for ($i = 0; $i -lt 5 -and -not [string]::IsNullOrEmpty($searchDir); $i++) {
            $candidate = [System.IO.Path]::Combine($searchDir, 'Runtime', $llrtBinaryName)
            if (Test-Path -Path $candidate -PathType Leaf) {
                $llrtCmd = $candidate
                break
            }
            $parentObj = [System.IO.Directory]::GetParent($searchDir)
            $searchDir = if ($null -ne $parentObj) { $parentObj.FullName } else { $null }
        }
    }

    if ($null -ne $llrtCmd) {
        if (-not $isWin -and (Get-Command chmod -ErrorAction SilentlyContinue)) {
            & chmod +x $llrtCmd 2>$null
        }

        Write-Host "`n[+] LLRT engine detected. Using LLRT for Layer 7 optimization..." @Net
        
        $scriptPath = [System.IO.Path]::Combine($PSScriptRoot, 'ScannerApplication.js')
        $tempFile = [System.IO.Path]::GetTempFileName()
        
        try {
            $jsonPayload = ConvertTo-Json -InputObject @($OpenPorts) -Depth 10 -Compress
            [System.IO.File]::WriteAllText($tempFile, $jsonPayload, [System.Text.UTF8Encoding]::new($false))
            
            $llrtOutput = (& $llrtCmd $scriptPath $tempFile) -join ""
            
            if (-not [string]::IsNullOrWhiteSpace($llrtOutput)) {
                $l7Output = @($llrtOutput | ConvertFrom-Json)
                
                if ($null -ne $l7Output -and $l7Output.Count -gt 0) {
                    $l7Output | ForEach-Object {
                        $dto = [HostResult]::new($_.Host)
                        $dto.Port = $_.Port
                        $dto.Service = $_.L4_Service
                        $dto.L7Banner = $_.L7_Banner
                        $dto
                    } | Sort-Object IPAddress, Port | Select-Object IPAddress, Port, Service, L7Banner | Format-Table -AutoSize
                } else {
                    Write-Host "`nNo service returns a banner at Layer 7 (LLRT Engine)." @Cha
                }
            } else {
                Write-Host "`nNo service returns a banner at Layer 7 (LLRT Engine)." @Cha
            }
        } catch {
            Write-Host "`n[!] LLRT execution failed. Error: $($_.Exception.Message)" @Pen
        } finally {
            if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force }
        }
    } else {
        Write-Host "`n[!] LLRT binary not found for current OS/Architecture ($arch)." @Cha
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