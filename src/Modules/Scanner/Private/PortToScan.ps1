function portToScan {
    $portsToScan = @()
        
    if ($quickScan) {
        $ConfigPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'Support', 'QuickScanPorts.psd1')
        $ConfigData = Import-PowerShellDataFile -Path $ConfigPath
        $portsToScan = [int[]]$ConfigData.QuickScanPorts
    }
    elseif ($ports -and $ports.Count -gt 0) {
        $portsToScan = [int[]]$ports
    }
    else {
        $portsToScan = [int[]]($pMin..$pMax)
    }
    
    return $portsToScan
}
