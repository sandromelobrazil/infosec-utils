param(
    [string] $packetCapturePath
)

[array] $packets = Get-Content $packetCapturePath | ConvertFrom-Csv | where {
    $_.dstIP -ne ("") -and
    $_.dstIP -notlike ("10.*") -and
    $_.dstIP -notlike ("192.168.*") -and
    $_.dstIP -notlike ("255.255.255.255") -and
    $_.dstIP -notlike ("224.0.0.*") -and
    $_.protNum -ne 2
}

Write-Host "[*] Searching for suspicious OUTBOUND (only) traffic to external IPs..." -ForegroundColor Yellow

if ($packets.Length -gt 0) {
    foreach ($packet in $packets) {
        $data = "No payload data"
        if ($packet.data -ne $null) { $data = $packet.data }
        Write-Host $packet.protDesc "  " $packet.time "`t" $packet.srcIP":"$packet.srcPort "  ->  " $packet.dstIP":" $packet.dstPort "`t(" $data ")"
    }
} else {
    Write-Host "[*] No suspicious traffic observed. You can still review the capture in full from the artefacts folder.`n"
}
