function Get-IpRange {
    [CmdletBinding()]
    param (
    	[Parameter(Mandatory = $true)]
    	[string] $Subnet
    )
    
    $regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$'
    
    if ($Subnet -notmatch $regex) {
        Write-Host "[!] Peringatan: Input '$Subnet' bukan format IP/CIDR yang valid (Maksimal CIDR adalah /32)." -ForegroundColor Yellow
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


function discoverCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    $reachableTargets = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()

    foreach ($target in $targets) {
        if ($target -match "/") {

            $ipRange = Get-IpRange -subnet $target

            $ipRange | ForEach-Object -Parallel {
                $ip = $_
                $localResult = $using:reachableTargets

                Write-Progress -Activity "Checking if $ip is reachable"

                $isReachable = $false
                $pingSender = [System.Net.NetworkInformation.Ping]::new()
                
                try {
                    for ($i = 0; $i -lt 2; $i++) {
                        $reply = $pingSender.Send($ip, 1000)
                        
                        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                            $isReachable = $true
                            break
                        }
                    }
                }
                catch {
                    $isReachable = $false 
                }
                finally {
                    $pingSender.Dispose()
                }

                if ($isReachable) {
                    $localResult[$ip] = $true
                }
                else {
                    $localResult[$ip] = $false
                    Write-Verbose "$ip is not reachable"
                }
            } -ThrottleLimit 15

            foreach ($ip in $ipRange | Sort-Object) {

                if ($reachableTargets[$ip]) {
                    Write-Host "$ip is reachable" -ForegroundColor Green
                }
                else {
                    Write-Verbose "$ip is not reachable"
                }
            }
        }
        else {

            $isReachableSingle = $false
            $pingSingle = [System.Net.NetworkInformation.Ping]::new()
            
            try {
                for ($i = 0; $i -lt 2; $i++) {
                    $reply = $pingSingle.Send($target, 1000)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $isReachableSingle = $true
                        break
                    }
                }
            }
            catch { $isReachableSingle = $false }
            finally { $pingSingle.Dispose() }
            
            if ($isReachableSingle) {
                Write-Host "$target is reachable" -ForegroundColor Green
                $reachableTargets[$target] = $true 
            }
            else {
                Write-Host "$target is not reachable" -ForegroundColor Yellow
            }
        }
    }

    if ($VerbosePreference -ne 'SilentlyContinue') {

        Write-Host "`nReachable Hosts:" -ForegroundColor Cyan

        foreach ($ip in $reachableTargets.Keys | Sort-Object) {
            if ($reachableTargets[$ip]) {
                Write-Host " - $ip"
            }
        }
    }
}
