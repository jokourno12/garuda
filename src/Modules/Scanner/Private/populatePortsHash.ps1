function populatePortsHash {
    $portsHashTable = @{}
 
    # Menggunakan Get-Content dengan error handling sederhana
    $lines = Get-Content -Path $PortListPath -ErrorAction SilentlyContinue
 
    foreach ($line in $lines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $HashTableData = $line.Split("|")
         
            if ($HashTableData.Count -ge 4) {
                try {
                    $port = [int]$HashTableData[0]
                    $value = "{0}|{1}" -f $HashTableData[2], $HashTableData[3]
                 
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