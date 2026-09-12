function internetProtocolRange {
    [CmdletBinding()]
    param (
    	[Parameter(Mandatory = $true)]
    	[string] $Subnet
    )
    
    $regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
    
    if ($Subnet -notmatch $regex) {
        throw "Critical: Input '$Subnet' not a valid IP/CIDR format."
    }

    $ip, $cidr = $subnet -split '/'
    $maskBits = [int]$cidr

    if ($maskBits -lt 16) {
        throw "Warning: CIDR /$maskBits too big. Garuda's maximum limit is /16 (65,534 hosts) per execution to maintain memory stability."
    }

    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    if ($maskBits -eq 0) {
        $maskInt = 0
    } else {
        $maskInt = [uint32]([uint32]::MaxValue -shl (32 - $maskBits))
    }

    $startIpInt = [uint32]($ipInt -band $maskInt)
    $wildcardInt = [uint32]([uint32]::MaxValue - $maskInt) 
    $endIpInt = [uint32]($startIpInt + $wildcardInt)
    
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