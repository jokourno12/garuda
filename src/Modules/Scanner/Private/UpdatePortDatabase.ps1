. "$([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'Runtime', 'Windows.ps1'))"

function updatePortDatabase {
    $needsUpdate = $true

    if (Test-Path -Path $PortListPath -PathType Leaf) {
        $fileInfo = Get-Item -Path $PortListPath
        
        if ($fileInfo.CreationTime -gt (Get-Date).AddDays(-28)) {
            Write-Verbose -Message "Read ports.txt and fill hash table..."
            $portsHashTable = populatePortsHash
            $needsUpdate = $false
        } else {
            Write-Host "File ports.txt outdated (>28 days). Updating data..." @Cha
        }
    } else {
        Write-Host "File ports.txt not found. Starting the creation process..." @Cha
    }

    if ($needsUpdate) {
        $modulePath = [System.IO.Path]::Combine($PSScriptRoot, '..\..', 'PortDatabase.psm1')

        if (-not (Get-Module -Name PortDatabase)) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }

        getWebPorts
        getVersion

        if (-not (Test-Path -Path $PortListPath -PathType Leaf)) {
            throw "Critical: getWebPorts failed to create or update $PortListPath"
        }

        Write-Host "[+] File ports.txt successfully created or updated." @App
        $portsHashTable = populatePortsHash
    }

    return $portsHashTable
}
