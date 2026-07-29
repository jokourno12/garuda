function scanner {
    param(
        [string[]]$targets,
        [switch]$quickScan,
        [int]$pMin,
        [int]$pMax,
        [string[]]$ports
    )

    # ARGUMENT VALIDATION
    if ($targets[0] -eq "") {
        Write-Host "You must specify at least one target with -targets.`nExiting now." -ForegroundColor Red
        exit
    }

    # DATABASE SERVICE PORT
    $PortListPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Support', 'ports.txt')

    . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'populatePortsHash.ps1')))"
    . "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'updatePortDatabase.ps1')))"

    $portsHashTable = updatePortDatabase

	# INITIALIZATION RESULT SCAN
    $result = [System.Collections.Concurrent.ConcurrentDictionary[object, object]]::new() #required for multithreading

    foreach ($target in $targets) {
        try {
    	    # Ambil IP pertama dari hasil resolusi DNS (Bisa IPv4 atau IPv6)
    	    $resolvedIP = [System.Net.Dns]::GetHostAddresses($target)[0]
    
    	    $TargetIP = $resolvedIP.IPAddressToString
    	    $TargetFamily = $resolvedIP.AddressFamily # Ini akan otomatis berisi InterNetwork atau InterNetworkV6
		}
		catch {
    	    Write-Warning "Gagal menemukan IP untuk host: $target. Melewati target ini..."
    		continue
	    }

        # PERSIAPAN ARRAY PORT 
        $portsToScan = @()
        
        if ($quickScan) {
            $ConfigPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Support', 'QuickScanPorts.psd1')
            $ConfigData = Import-PowerShellDataFile -Path $ConfigPath
            $portsToScan = [int[]]$ConfigData.QuickScanPorts
        }
        elseif ($ports -and $ports.Count -gt 0) {
            $portsToScan = [int[]]$ports
        }
        else {
            $portsToScan = [int[]]($pMin..$pMax)
        }

        $totalPorts = $portsToScan.Count

        # Pastikan ada port yang akan di-scan untuk menghindari error perhitungan
        if ($totalPorts -gt 0) {
            
            # SINGLE SCAN ENGINE (Mengulang berdasarkan Index untuk akurasi persentase)
            0..($totalPorts - 1) | ForEach-Object -Parallel {
                $index = $_
                $portsToScan = $using:portsToScan
                $port = $portsToScan[$index]
                
                $Target = $using:target           # Nama host (untuk output)
                $TargetIP = $using:TargetIP       # IP Address murni (untuk koneksi)
				$TargetFamily = $using:TargetFamily
                $portsHashTable = $using:portsHashTable
                $portInt = [Int] $port
                $localResult = $using:result
                $totalPorts = $using:totalPorts

                # TAMPILAN VISUAL INTERAKTIF DENGAN PERSENTASE
                $completed = (($index + 1) / $totalPorts) * 100
                Write-Progress -Activity "Scanning ${Target}:$port" -Status "$([math]::Round($completed, 2))% complete" -PercentComplete $completed

                # TCP CONNECTION
                $obj = [System.Net.Sockets.Socket]::new(
                    $TargetFamily, 
                    [System.Net.Sockets.SocketType]::Stream, 
                    [System.Net.Sockets.ProtocolType]::Tcp
                )

                $obj.NoDelay = $true
                $obj.SendTimeout = 100
                $obj.ReceiveTimeout = 100

                # [PERBAIKAN KONEKSI LOW-LEVEL]
                $ip = [System.Net.IPAddress]::Parse($TargetIP)
                $endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                
                try {
                    # Koneksi memanggil $endpoint langsung, bukan $Target, menghindari DNS lookup berulang
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
                            # Server membalas dengan cepat, tetapi berupa penolakan (TCP RST)
                            Write-Verbose -Message "$Target 'port' $port 'Closed - Refused'" -Verbose
                        }
                    }
                }
				catch {
    		        Write-Verbose -Message "$Target 'port' $port 'Error: $($_.Exception.Message)'" -Verbose
		        }
                finally {
                    $obj.Close()
                    $obj.Dispose()
                }
            } -ThrottleLimit 15
        }
    }

    # OUTPUT RENDERER
    $result.Values | Sort-Object host, port | Format-Table -AutoSize
}
