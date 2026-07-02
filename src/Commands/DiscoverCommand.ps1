function Get-IpRange {
    param (
        [string] $subnet
    )
    
    $ip, $cidr = $subnet -split '/'
    $maskBits = [int]$cidr
    $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $maskInt = ([math]::Pow(2, $maskBits) - 1) -shl (32 - $maskBits)
    $startIpInt = $ipInt -band $maskInt
    $endIpInt = $startIpInt -bor -bnot($maskInt)
    
    for ($i = $startIpInt; $i -le $endIpInt; $i++) {
        $bytes = [BitConverter]::GetBytes($i)
        [Array]::Reverse($bytes)
        [System.Net.IPAddress]::new($bytes).ToString()
    }
}


function discoverCommand {

    if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('targets')) {
        Write-Host "When using -discover, the only other allowed flag is -targets." -ForegroundColor Red
        return
    }

    $reachableTargets = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()

    foreach ($target in $targets) {

        if ($target -match "/") {

            $ipRange = Get-IpRange -subnet $target

            $ipRange | ForEach-Object -Parallel {

                $ip = $_
                $localResult = $using:reachableTargets

                Write-Progress -Activity "Checking if $ip is reachable"

                if (Test-Connection -ComputerName $ip -Count 2 -Quiet -TimeoutSeconds 1) {
                    $localResult[$ip] = $true
                }
                else {
                    $localResult[$ip] = $false
                    Write-Verbose "$ip is not reachable"
                }

            } -ThrottleLimit 15

            foreach ($ip in $reachableTargets.Keys | Sort-Object) {

                if ($reachableTargets[$ip]) {
                    Write-Host "$ip is reachable" -ForegroundColor Green
                }
                else {
                    Write-Verbose "$ip is not reachable"
                }

            }

        }
        else {

            if (Test-Connection -ComputerName $target -Count 2 -Quiet) {
                Write-Host "$target is reachable" -ForegroundColor Green
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
