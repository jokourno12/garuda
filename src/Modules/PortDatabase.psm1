. "$([System.IO.Path]::Combine($PSScriptRoot, '..', 'Runtime', 'Windows.ps1'))"

function getWebPorts {

    $client = [System.Net.Http.HttpClient]::new()
    
    $client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    
    try {
        Write-Host "Downloading port database from IANA..." @Pen
        
        $xmlString = $client.GetStringAsync("https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml").Result
        
        if ([string]::IsNullOrWhiteSpace($xmlString)) {
            throw "XML data downloaded from IANA is empty. Check your internet connection or the possibility that the IANA server is down."
        }

        [xml]$LatestPorts = [System.Xml.XmlDocument]::new()
        $LatestPorts.LoadXml($xmlString)

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
    catch {
        Write-Error "Failed to process Web Ports data. Detail: $($_.Exception.Message)"
        throw $_
    }
    finally {
        if ($null -ne $client) { $client.Dispose() }
    }
}

function getVersion {
    $localModulePath = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'package.psd1')
    $remoteModuleUrl = "https://raw.githubusercontent.com/jokourno12/garuda/main/package.psd1"

    $client = [System.Net.Http.HttpClient]::new()
    
    try {
        $localModule = Import-PowerShellDataFile -Path $localModulePath
        $localVersion = [version]$localModule.ModuleVersion

        $stringContent = $client.GetStringAsync($remoteModuleUrl).Result
        $remoteModuleContent = [PSCustomObject]@{ Content = $stringContent }
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($remoteModuleContent.Content, [ref]$null, [ref]$null)
        $remoteModule = $ast.EndBlock.Statements[0].PipelineElements[0].Expression.Value

        $remoteVersion = [version]$remoteModule.ModuleVersion

        if ($localVersion.Major -lt $remoteVersion.Major) {
            Write-Host "A new version ($remoteVersion) is available. Please update your module." @Cha
        }          
    }
    catch {
        Write-Warning "Failed to check for version update. Detail: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $client) { $client.Dispose() }
    }         
}
