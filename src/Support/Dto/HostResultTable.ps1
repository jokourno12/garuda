function hostResultTable {
    param(
        [array]$Results,
        [bool]$ShowMac = $false,
        [bool]$ShowClassification = $false
    )

    if (-not $Results -or $Results.Count -eq 0) { return }

    Write-Host ""
    $headerIP    = "IP Address".PadRight(16)
    $headerProto = "Protocol".PadRight(14)
    $headerMac   = if ($ShowMac) { "MAC Address".PadRight(20) } else { "" }
    $headerClass = if ($ShowClassification) { "Inferred Classification" } else { "" }

    $headerStr = "$headerIP $headerProto $headerMac $headerClass".TrimEnd()
    Write-Host " $headerStr" @App
    Write-Host " $("-" * $headerStr.Length)" @Dim

    $sortedResults = $Results | Sort-Object { 
        if ($_.IPAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { 
            [version]$_.IPAddress 
        } 

        else { 
            $_.IPAddress 
        } 
    }

    foreach ($item in $Results) {
        if ($item.IsReachable) {
            $colIP    = $item.IPAddress.PadRight(16)
            $colProto = $item.GetDisplayProtocol().PadRight(14)
            $colMac   = if ($ShowMac) { $item.MACAddress.PadRight(20) } else { "" }
            $colClass = if ($ShowClassification) { $item.InferredClassification } else { "" }

            $rowStr = "$colIP $colProto $colMac $colClass".TrimEnd()
            Write-Host " $rowStr" @App
        }
    }
}