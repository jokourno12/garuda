function populatePortsHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PortListPath
    )

    $portsHashTable = @{}

    if (-not (Test-Path -Path $PortListPath -PathType Leaf)) {
        Write-Warning "[Garuda] Port list file not found: $PortListPath"
        return $portsHashTable
    }
  
    try {
        $lines = Get-Content -Path $PortListPath -ErrorAction Stop
        
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
                        Write-Debug "Failed to process line: $line"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "[Garuda] An error occurred while reading the port file: $_"
    }

    return $portsHashTable
}
