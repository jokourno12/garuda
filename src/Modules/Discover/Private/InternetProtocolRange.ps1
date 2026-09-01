function internetProtocolRange {
    [CmdletBinding()]
    param (
    	[Parameter(Mandatory = $true)]
    	[string] $Subnet
    )
    
    $regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
    
    if ($Subnet -notmatch $regex) {
        Write-Host "[!] Peringatan: Input '$Subnet' bukan format IP/CIDR yang valid (Maksimal CIDR adalah /32)." @Cha
        return
    }

    $ip, $cidr = $subnet -split '/'
    $maskBits = [int]$cidr

    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    $maskInt = [uint32]([uint32]::MaxValue -shl (32 - $maskBits))

    $startIpInt = [uint32]($ipInt -band $maskInt)
    $endIpInt = [uint32]($startIpInt -bor (-bnot $maskInt))
    
    if ($maskBits -lt 31) {
        $startIpInt += 1
        $endIpInt -= 1
    }

    for ($i = $startIpInt; $i -le $endIpInt; $i++) {
        $bytes = [BitConverter]::GetBytes([uint32]$i)
        [Array]::Reverse($bytes)
        [System.Net.IPAddress]::new($bytes).ToString()
    }
}