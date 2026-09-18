# Dawn - Subnet Sweep / Host Discovery (/24 Full Range)
# Note: Prone to triggering ISP rate-limiting if executed against public targets (WAN).
$ThrottleDawn  = @{ ThrottleLimit = 254 }

# Creat - Balanced L7 & Structured Service Mapping
# Note: Default mode. High parallel packet queues on WAN risk causing timeout/latency jitter.
$ThrottleCreat = @{ ThrottleLimit = 64 }

# Night - Stealth / Background Low-Noise Probing
# Note: Stealth mode. Highly effective for evading packet drops by target WAF and IPS.
$ThrottleNight = @{ ThrottleLimit = 3 }

# Woman - Legacy / Sensitive Systems (Sequential Precision)
# Note: Extremely slow and accurate. Guarantees immunity from local NAT overflow and socket exhaustion.
$ThrottleWoman = @{ ThrottleLimit = 1 }

# Spite - Maximum Throughput / Brutal LAN Scanning
# Note: LAN EXCLUSIVE. Will instantly trigger local NAT buffer overflow and system exhaustion if routed to the internet.
$ThrottleSpite = @{ ThrottleLimit = 666 }