function updatePortDatabase {
    $needsUpdate = $true

    if (Test-Path -Path $PortListPath -PathType Leaf) {
        $fileInfo = Get-Item -Path $PortListPath
        
        if ($fileInfo.CreationTime -gt (Get-Date).AddDays(-28)) {
            Write-Verbose -Message "Read ports.txt and fill hash table..."
            $portsHashTable = populatePortsHash
            $needsUpdate = $false
        } else {
            Write-Host "File ports.txt sudah usang (>28 hari). Memperbarui data..."
        }
    } else {
        Write-Host "File ports.txt tidak ditemukan. Memulai proses pembuatan..."
    }

    if ($needsUpdate) {
        # Pastikan modul dimuat
        $modulePath = [System.IO.Path]::Combine($PSScriptRoot, '..\..', 'PortDatabase.psm1')

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

    # Satu-satunya tambahan: Kita harus melempar hasil $portsHashTable ke pemanggil
    return $portsHashTable
}