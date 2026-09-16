function portToScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$QuickScan,

        [Parameter(Mandatory = $false)]
        [int[]]$Ports,

        [Parameter(Mandatory = $false)]
        [int]$PMin = 1,

        [Parameter(Mandatory = $false)]
        [int]$PMax = 65535
    )

    $portsToScan = @()
        
    if ($quickScan) {
        $ConfigPath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'Support', 'QuickScanPorts.psd1')
        
        if (Test-Path -Path $ConfigPath -PathType Leaf) {
            try {
                $ConfigData = Import-PowerShellDataFile -Path $ConfigPath -ErrorAction Stop
                $portsToScan = [int[]]$ConfigData.QuickScanPorts
            }
            catch {
                Write-Warning "[Garuda] Failed to read configuration QuickScanPorts.psd1: $_"
            }
        } else {
            Write-Warning "[Garuda] QuickScan configuration file not found in: $ConfigPath"
        }
    }
    elseif ($null -ne $Ports -and $Ports.Count -gt 0) {
        $portsToScan = [int[]]$ports
    }
    else {
        if ($PMin -le $PMax) {
            $portsToScan = [int[]]($PMin..$PMax)
        } else {
            Write-Warning "[Garuda] Invalid port range ($PMin greater than $PMax)."
        }
    }
    
    return $portsToScan
}
