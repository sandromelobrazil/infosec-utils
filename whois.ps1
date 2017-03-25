$Global:PROXY_HOST = "proxyURL"

function sendGETRequest($URL) {
    $response = Invoke-WebRequest -Uri $URL -Headers $Global:HEADERS -Proxy $Global:PROXY_HOST -ProxyUseDefaultCredentials
    return $response
}

function fetchAllDNSRecords($hostname) {
    $recordsToLookUp = (
        "A", 
        "MX", 
        "NS", 
        "TXT", 
        "SOA"
    )
    
    $recordsToLookUp.ForEach({
        $dnsRecords = getDNSRecordsForHost $hostname $_
        $dnsRecords = ConvertFrom-Json $dnsRecords.Content
        printDNSrecords $dnsRecords
    })
}

function getDNSRecordsForHost($hostname, $type) {
    $baseUrl = "https://dns-api.org/"
    $type += "/"
    $url = $baseUrl + $type + $hostname
    $dnsRecordsRaw = sendGETRequest $url
    
    return $dnsRecordsRaw
}

function printDNSrecords($dnsRecords) {
    $dnsRecords.foreach({
        Write-Host $_.type "`t" $_.value "`t" $_.name
    })
}

if ($args[0] -ne "") {
    fetchAllDNSRecords $args[0]
}