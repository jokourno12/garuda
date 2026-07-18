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
    $PortListPath = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Support', 'ports.txt')

function populatePortsHash {
    $portsHashTable = @{}
    
    # Menggunakan Get-Content dengan error handling sederhana
    $lines = Get-Content -Path $PortListPath -ErrorAction SilentlyContinue
    
    foreach ($line in $lines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $HashTableData = $line.Split("|")
            
            # Memastikan array memiliki setidaknya 4 elemen sebelum diproses
            if ($HashTableData.Count -ge 4) {
                try {
                    # Mengonversi port ke [int]
                    $port = [int]$HashTableData[0]
                    $value = "{0}|{1}" -f $HashTableData[2], $HashTableData[3]
                    
                    # Menggunakan assignment langsung untuk menghindari error .add()
                    $portsHashTable[$port] = $value
                }
                catch {
                    Write-Warning "Gagal memproses baris: $line"
                }
            }
        }
    }
    return $portsHashTable
}


    if ((Test-Path -Path $PortListPath -PathType Leaf -ErrorAction SilentlyContinue) -and ((Get-Item $PortListPath -ErrorAction SilentlyContinue).CreationTime -gt (Get-Date).AddDays(-28))) {
    Write-Verbose -Message "Read ports.txt and fill hash table..."
    $portsHashTable = populatePortsHash
    }
    else {
# Memberikan feedback yang informatif berdasarkan kondisi
    if (-not $fileInfo) {
        Write-Host "File ports.txt tidak ditemukan. Memulai proses pembuatan..."
    } else {
        Write-Host "File ports.txt sudah usang (>28 hari). Memperbarui data..."
    }

    # Pastikan modul dimuat
    $modulePath = Join-Path $PSScriptRoot "PortDatabase.psm1"
    if (-not (Get-Module -Name PortDatabase)) {
        Import-Module $modulePath -Force -ErrorAction Stop
    }

    # Jalankan proses update
    getWebPorts
    getVersion

    # Cek sekali saja setelah proses update
    if (-not (Test-Path -Path $PortListPath -PathType Leaf)) {
        throw "Kritis: getWebPorts gagal membuat atau memperbarui $PortListPath"
    }

    Write-Host "[+] File ports.txt berhasil dibuat atau diperbarui." -ForegroundColor Green
    $portsHashTable = populatePortsHash
    }

# INITIALIZATION RESULT SCAN
    $result = [System.Collections.Concurrent.ConcurrentDictionary[object, object]]::new() #required for multithreading

    foreach ($target in $targets) {
        
        # [PERBAIKAN DNS RESOLUTION] - Resolve DNS di luar loop parallel untuk menghindari overhead
        try {
    	    # Ambil IP pertama dari hasil resolusi DNS (Bisa IPv4 atau IPv6)
    	    $resolvedIP = [System.Net.Dns]::GetHostAddresses($target)[0]
    
    	    $TargetIP = $resolvedIP.IPAddressToString
    	    $TargetFamily = $resolvedIP.AddressFamily # Ini akan otomatis berisi InterNetwork atau InterNetworkV6
	} catch {
    	    Write-Warning "Gagal menemukan IP untuk host: $target. Melewati target ini..."
    continue
	}

        # PERSIAPAN ARRAY PORT 
        $portsToScan = @()
        
        if ($quickScan) {
            $ConfigPath = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Support', 'QuickScanPorts.psd1')
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
                }
                
            } -ThrottleLimit 15
        }
    }

    # OUTPUT RENDERER
    $result.Values | Sort-Object host, port | Format-Table -AutoSize
}
