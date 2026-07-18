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
                
                $Target = $using:target
                $portsHashTable = $using:portsHashTable
                $portInt = [Int] $port
                $localResult = $using:result
                $totalPorts = $using:totalPorts

                # TAMPILAN VISUAL INTERAKTIF DENGAN PERSENTASE
                $completed = (($index + 1) / $totalPorts) * 100
                Write-Progress -Activity "Scanning ${Target}:$port" -Status "$([math]::Round($completed, 2))% complete" -PercentComplete $completed

                # TCP CONNECTION
                $obj = [System.Net.Sockets.Socket]::new(
    				[System.Net.Sockets.AddressFamily]::InterNetwork, 
    				[System.Net.Sockets.SocketType]::Stream, 
    				[System.Net.Sockets.ProtocolType]::Tcp
				)

				$obj.NoDelay = $true
				$obj.SendTimeout = 100
				$obj.ReceiveTimeout = 100

				$ip = [System.Net.IPAddress]::Parse($Target)
				$endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                
                try {
                    $connect = $obj.BeginConnect($Target, $port, $null, $null)
                    $Wait = $connect.AsyncWaitHandle.WaitOne(100, $false)

                    if (-not $Wait) {
                        Write-Verbose -Message "$Target 'port' $port 'Closed - Timeout'" -Verbose
                    }
                    else {
                        $value = "Open"
                        Write-Verbose -Message "$Target 'port' $port Open'" -Verbose

                        if ($portsHashTable.ContainsKey($portInt)) {
                            $Service = $portsHashTable[$portInt].Split('|')
                        }
                        else {
                            $Service = @("Unknown", "Unknown")
                        }

                        # Result Object Builder (Logic Asli)
                        $r = New-Object -type psobject
                        $r | Add-Member -MemberType NoteProperty -name Host -value $Target
                        $r | Add-Member -MemberType NoteProperty -name Port -value $port
                        $r | Add-Member -MemberType NoteProperty -name State -value $value
                        $r | Add-Member -MemberType NoteProperty -name Service -value $Service[0]
                        $r | Add-Member -MemberType NoteProperty -name "IANA Standard Description" -value $Service[1]

                        $key = $Target + ":" + $port
                        $localResult[$key] = $r
                    }
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
