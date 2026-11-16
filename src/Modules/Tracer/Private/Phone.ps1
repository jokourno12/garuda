function Resolve-PhoneMetadata {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Number
    )

    $e164 = $Number
    $local = $Number
    $country = 'Unknown'
    $operator = 'Unknown'

    # Normalisasi format Indonesia (08... <-> +628...)
    if ($Number -match '^0(8\d{7,11})$') {
        $e164 = "+62$($Matches[1])"
        $local = $Number
        $country = 'Indonesia (+62)'
    }
    elseif ($Number -match '^\+62(8\d{7,11})$') {
        $e164 = $Number
        $local = "0$($Matches[1])"
        $country = 'Indonesia (+62)'
    }
    elseif ($Number -match '^\+([1-9]\d{0,2})\d+$') {
        $country = "International (+$($Matches[1]))"
    }

    # Pemetaan prefix operator seluler Indonesia (berdasarkan format lokal 08xx)
    if ($local -match '^(08\d{2})') {
        $prefix = $Matches[1]
        $operator = switch -Regex ($prefix) {
            '^08(11|12|13|21|22|23|51|52|53)' { 'Telkomsel'; break }
            '^08(14|15|16|55|56|57|58)'       { 'Indosat Ooredoo Hutchison'; break }
            '^08(17|18|19|59|77|78)'          { 'XL Axiata'; break }
            '^08(31|32|33|38)'                { 'AXIS (XL Axiata)'; break }
            '^08(95|96|97|98|99)'             { 'Tri (Indosat)'; break }
            '^08(81|82|83|84|85|86|87|88|89)' { 'Smartfren'; break }
            default                           { 'Other / Virtual Operator' }
        }
    }

    return [PSCustomObject]@{
        RawInput = $Number
        E164     = $e164
        Local    = $local
        Country  = $country
        Operator = $operator
    }
}

function Get-PhoneOsintHints {
    param (
        [Parameter(Mandatory = $true)]
        [string]$E164,

        [Parameter(Mandatory = $true)]
        [string]$Local
    )

    $waNumber = $E164 -replace '^\+', ''

    return [PSCustomObject]@{
        WhatsAppUrl = "https://wa.me/$waNumber"
        GoogleDork  = "`"$E164`" OR `"$Local`""
    }
}

function phone {
    param (
        [Parameter(Mandatory = $true)]
        [string]$target
    )

    Write-Host "`n[*] Analyzing Phone Metadata..." @Cha
    $meta = Resolve-PhoneMetadata -Number $target

    Write-Host "    E.164 Format : $($meta.E164)"
    Write-Host "    Local Format : $($meta.Local)"
    Write-Host "    Country      : $($meta.Country)"
    Write-Host "    Carrier/Op   : $($meta.Operator)"

    Write-Host "`n[*] Generating Passive OSINT Pivots..." @Cha
    $osint = Get-PhoneOsintHints -E164 $meta.E164 -Local $meta.Local

    Write-Host "    Direct Chat  : $($osint.WhatsAppUrl)"
    Write-Host "    Search Dork  : $($osint.GoogleDork)"
}