. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Tracer', 'Tracer.ps1')))"

function tracerCommand {
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$entity
    )

    $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    $phonePattern = '^(\+?[1-9]\d{7,14}|0\d{8,13})$'
    $urlPattern   = '^https?://[^\s/$.?#].[^\s]*$'

    foreach ($item in $entity) {
        $cleanItem = $item.Trim()
        $normalizedPhone = $cleanItem -replace '[\s\-\(\)]', ''
        $uriObj = $null

        switch -Regex ($cleanItem) {
            $emailPattern {
                Write-Host "[+] Valid Email detected: $cleanItem" @Cha
                tracer -email $cleanItem
                break
            }
            { $normalizedPhone -match $phonePattern } {
                Write-Host "[+] Valid Phone detected: $normalizedPhone" @Cha
                tracer -phone $normalizedPhone
                break
            }
            { ($cleanItem -match $urlPattern) -and ([System.Uri]::TryCreate($cleanItem, [System.UriKind]::Absolute, [ref]$uriObj)) -and ($uriObj.Host -match '\.') } {
                Write-Host "[+] Valid URL detected: $cleanItem" @Cha
                tracer -url $cleanItem
                break
            }
            default {
                Write-Host "Error: Invalid object '$cleanItem'." @Pen
                Write-Host "Supported formats:" @Cha
                Write-Host "Email (e.g., user@domain.com)" @Cha
                Write-Host "Phone (e.g., +628123456789, 08123456789)." @Cha
                Write-Host "URL (e.g., https://example.com)." @Cha
            }
        }
    }
}