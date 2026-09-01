. "$([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'Runtime', 'Windows.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'InternetProtocolRange.ps1'))"

function discover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    $reachableTargets = [System.Collections.Concurrent.ConcurrentDictionary[string, bool]]::new()

    foreach ($target in $targets) {
        if ($target -match "/") {

            $ipRange = internetProtocolRange -subnet $target

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
                    Write-Host "$ip is reachable" @App
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
                Write-Host "$target is reachable" @App
                $reachableTargets[$target] = $true 
            }
            else {
                Write-Host "$target is not reachable" @Cha
            }
        }
    }

    if ($VerbosePreference -ne 'SilentlyContinue') {

        Write-Host "`nReachable Hosts:" @Net

        foreach ($ip in $reachableTargets.Keys | Sort-Object) {
            if ($reachableTargets[$ip]) {
                Write-Host " - $ip"
            }
        }
    }
}
