class HostResult {
    [string]$IPAddress
    [string]$Protocol
    [int]$TTL
    [string]$MACAddress
    [string]$InferredClassification
    [bool]$IsReachable
    [datetime]$Timestamp

    HostResult([string]$ip) {
        $this.IPAddress      = $ip
        $this.Protocol       = "None"
        $this.TTL            = 0
        $this.MACAddress     = "N/A"
        $this.InferredClassification = "Unknown Host"
        $this.IsReachable    = $false
        $this.Timestamp      = [datetime]::Now
    }

    [string] GetDisplayProtocol() {
        if ($this.Protocol -eq "ICMP" -and $this.TTL -gt 0) {
            return "ICMP ($($this.TTL))"
        }
        return $this.Protocol
    }

    [void] InferClassification() {
        $localTtl = $this.TTL
        $localIp = $this.IPAddress
        
        $isInternal = $localIp -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)'

        if ($this.MACAddress -eq 'FF-FF-FF-FF-FF-FF') { 
            $this.InferredClassification = "Broadcast" 
        }
        elseif ($localTtl -eq 0 -and $this.Protocol -match 'TCP') { 
            $this.InferredClassification = "Filtered Host" 
        }
        elseif (-not $isInternal) {
            $this.InferredClassification = "Public Endpoint"
        }
        elseif ($localIp -match '\.(1|254)$' -and $localTtl -gt 128) { 
            $this.InferredClassification = "Gateway" 
        }
        elseif ($localTtl -gt 128 -and $localTtl -le 255) { 
            $this.InferredClassification = "Network Infrastructure" 
        }
        elseif ($localTtl -gt 64 -and $localTtl -le 128) { 
            $this.InferredClassification = "Windows OS" 
        }
        elseif ($localTtl -gt 0 -and $localTtl -le 64) { 
            $this.InferredClassification = "Linux / Unix / Mobile" 
        }
    }
}