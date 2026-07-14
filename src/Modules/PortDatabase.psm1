function Get-WebPorts {

    $client = [System.Net.Http.HttpClient]::new()
$stream = $client.GetStreamAsync("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml").Result

    [xml]$LatestPorts = [System.Xml.XmlDocument]::new()
    $LatestPorts.Load($stream)

    $output = [System.Text.StringBuilder]::new()
    
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
                [void]$output.AppendFormat("{0}|{1}|{2}|{3}`n", $number1, $record.protocol, $record.name, $description)
            }
        }
        else {
            [void]$output.AppendFormat("{0}|{1}|{2}|{3}`n", $number, $record.protocol, $record.name, $description)
        }
    }
    Write-Progress -Activity "Processing records" -Status "Getting port descriptions from the web $percentComplete%" -Completed

    $portsPath = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Support', 'ports.txt')
    
    [System.IO.File]::WriteAllText($portsPath, $output.ToString())
    Write-Verbose -Message "File created at $portsPath"
}

function get-Version {
    $localModulePath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'package.psd1')
    $remoteModuleUrl = "https://raw.githubusercontent.com/jokourno12/garuda/main/package.psd1"

    $localModule = Import-PowerShellDataFile -Path $localModulePath
    $localVersion = [version]$localModule.ModuleVersion

    $client = [System.Net.Http.HttpClient]::new()
    $stringContent = $client.GetStringAsync($remoteModuleUrl).Result
    $remoteModuleContent = [PSCustomObject]@{ Content = $stringContent }
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($remoteModuleContent.Content, [ref]$null, [ref]$null)
    $remoteModule = $ast.EndBlock.Statements[0].PipelineElements[0].Expression.Value

    $remoteVersion = [version]$remoteModule.ModuleVersion

    if ($localVersion.Major -lt $remoteVersion.Major) {
        Write-Host "A new version ($remoteVersion) is available. Please update your module." -ForegroundColor Yellow
    }         
}