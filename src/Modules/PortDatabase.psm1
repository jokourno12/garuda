function Get-WebPorts {

    $client = [System.Net.Http.HttpClient]::new()
    $stream = $client.GetStreamAsync("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml").Result

    [xml]$LatestPorts = [System.Xml.XmlDocument]::new()
    $LatestPorts.Load($stream)

    $output = ""
    $total = $LatestPorts.ChildNodes.record.Count
    $current = 0
    foreach ($record in $LatestPorts.ChildNodes.record){
        $current++
        $percentComplete = [math]::Round(($current / $total) * 100, 2)
        Write-Progress -Activity "Processing records" -Status "Getting port descriptions from the web $percentComplete%" -PercentComplete $percentComplete
        if ([string]::IsNullOrEmpty($record.number) -or ([string]::IsNullOrEmpty($record.protocol))) {
            continue
        }

        $description = ($record.description -replace '`n','') -replace '\s+',' '

        $number = $record.number

        if ($number -like "*-*") {
            $numberArr = $number.Split('-')

            foreach($number1 in $numberArr[0]..$numberArr[1]) {
                $output += "$number1|$($record.protocol)|$($record.name)|$description`n"
            }
        }
        
        else {
            $output += "$number|$($record.protocol)|$($record.name)|$description`n"
        }
    }
    Write-Progress -Activity "Processing records" -Status "Getting port descriptions from the web $percentComplete%" -Completed

    $portsPath = Join-Path $PSScriptRoot '..\Support\ports.txt'
    Out-File -InputObject $output -FilePath $portsPath
    Write-Verbose -Message "File created at $portsPath"
}

function get-Version {
    $localModulePath = Join-Path $PSScriptRoot '..\..\package.psd1'
    $remoteModuleUrl = "https://raw.githubusercontent.com/jokourno12/garuda/main/package.psd1"

    $localModule = Import-PowerShellDataFile -Path $localModulePath
    $localVersion = [version]$localModule.ModuleVersion

    $remoteModuleContent = Invoke-WebRequest -Uri $remoteModuleUrl -UseBasicParsing
    $remoteModule = Invoke-Expression $remoteModuleContent.Content
    $remoteVersion = [version]$remoteModule.ModuleVersion

    if ($localVersion.Major -lt $remoteVersion.Major) {
        Write-Host "A new version ($remoteVersion) is available. Please update your module." -ForegroundColor Yellow
    }         
}
