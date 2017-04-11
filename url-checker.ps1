# Maintained by Mantvydas.Baranauskas@usbank.com;
# Inspired by and translated from Melissa's SmartyPants Python Script;

Param(
    [string] $url,
    [switch] $domainonly,
    [switch] $ironportonly
)

. "C:\splunk.ps1"

$Global:PASSWORD = ConvertTo-SecureString "x!" -AsPlainText -Force
$Global:PROXY_USER = $env:USERNAME
$Global:CREDENTIALS = New-Object System.Management.Automation.PSCredential ($Global:PROXY_USER, $Global:PASSWORD)
$Global:PROXY_HOST = "x"
$Global:shouldFetchIrontPortEventsCount = $false
$Global:HEADERS = @{
        "Accept-Encoding" = "gzip, deflate"
        "User-Agent" = "Mantvydas B. Powershell URL Reporter"
}

function processCommandLineParams($url) {
    if ($url -ne "") {
        if ($domainonly) {
            $url = (extractDomainFromURL $url)
        }
        if ($ironportonly) {
            Write-Host "Counting events in IronPort for:" $url
            $Global:shouldFetchIrontPortEventsCount = $true
            getEventsCountInIronPort $url
        } else {
            Write-Host $url being analysed...
            getAllReportsForURL $url
        }
    }
}

function getAllReportsForURL($targetURL, $userName) {
    $Global:shouldFetchIrontPortEventsCount = $false
    $reports = @{
        virusTotal = getVirusTotalReportForURL $targetURL
        urlVoid = getURLVoidReportForUrl $targetURL
        ironPort = getEventsCountInIronPort $targetURL
    }
  
    return $reports
}

function getEventsCountInIronPort($URL) {
    $sanitisedURL = sanitiseURL $URL
    
    if ($URL -notlike "*google*" -and $URL -notlike "*bing*" -and $Global:shouldFetchIrontPortEventsCount) {
        $searchQuery = 'earliest=-7d ' + $URL
        $splunkLogs = fetchLogsForSplunkSearchQuery $searchQuery
        
        if ([array] $splunkLogs -ne $null) {
            $report = "Events found on IronPort in the last 7 days: " + $splunkLogs.Count
            
            if ($splunkLogs.Count -eq $null) {
                $report = "1 event found on IronPort in the last 7 days"
            }
        } 
        else {
            $report = "No events found on IronPort in the last 7 days"
        }
        return $report + " ( " + $sanitisedURL + " )"

    } else {
        return $sanitisedURL + " seems to be safe, so no IronPort activity requested."
    }
}

function sendGETRequest($URL) {
    $response = Invoke-WebRequest -Uri $URL -Headers $Global:HEADERS -Proxy $Global:PROXY_HOST -ProxyUseDefaultCredentials
    return $response
}

function sendPOSTRequest($URL, $parameters, $headers) {
    $response = Invoke-WebRequest -Uri $URL -Method POST -Body $parameters -Proxy $Global:PROXY_HOST -ProxyUseDefaultCredentials
    return $response
}

function getVirusTotalReportForURL($targetURL) {
    $baseUrl = "http://www.virustotal.com/vtapi/v2/url/report"
    $apiKey = "3c38b131e208664c2c49b6c071670bc777a8c295e5e711197c42f230380cc6a1"
    $sanitisedURL = sanitiseURL $targetURL

    $requestParameters = @{
        apikey = $apiKey
        resource = $targetURL
    }

    $response = sendPOSTRequest $baseUrl $requestParameters
    $responseJson = ConvertFrom-Json $response.content
    
    if ($responseJson.response_code -ne 0) {
        $detectedByServices = getServicesDetected $responseJson.scans
    
        $detectedByServices.forEach({
            if ($_.GetType().Name -ne "Int32") {
                if ($_.value.detected -eq $true) {
                    $report = $report + $_.ServiceName + ", "
                }
            }
        })
        
        if ($report.Length -lt 3) {
                $finalReport = "✔ VirusTotal - Clean"
        } else {
            $finalReport = "⚠ VirusTotal - Identified by: " + $report
            $Global:shouldFetchIrontPortEventsCount = $true
        }
    } else {
        $finalReport = "VirusTotal - Not found in the dataset."
    }
    $finalReport += " ( " + $sanitisedURL + " )"

    return $finalReport
}

function getServicesDetected($servicesList) {
    [System.Collections.ArrayList] $detectedByServices = "item", "item2"
    $detectedByServices.Clear()
    
    if ($servicesList -ne $null) {
        $services = Get-Member -InputObject $servicesList -MemberType NoteProperty
        
        foreach ($service in $services) {
            $serviceValue = $servicesList | Select-Object -ExpandProperty $service.Name
            $serviceToAdd = @{
                serviceName = $service.Name
                value = $serviceValue
            }
            $detectedByServices.Add($serviceToAdd)
        }
        
        return $detectedByServices
    }
}

function sanitiseURL($URL) {
    $sanitisedURL = $URL -replace("\.","[.]")
    return $sanitisedURL
}

function extractDomainFromURL($URL) {
    $URLcontainsHTTP = $URL -match '(https?:\/\/|https?%3A%2F%2F|www.)([\w\d.-]+)'
    
    if ($URLcontainsHTTP) { 
        $domain = $Matches[2] -replace ("www.","")
    } else {
        $domain = $URL
    }

    return $domain
}

function getURLVoidReportForUrl($targetURL) {
    $apiKey = "x"
    $baseUrl = "http://api.urlvoid.com/api1000/" + $apiKey + "/host/"
    $domain = extractDomainFromURL $targetURL
    $URL = $baseUrl + $domain

    $requestParameters = @{
        apikey = $apiKey
        resource = $URL
    }

    $response = sendGETRequest $URL
    [xml] $response = $response.content
    $detectedByEngines = $response.response.detections.engines.engine
    $sanitisedDomain = sanitiseURL $domain

    if ($detectedByEngines -ne $null) {
        $report = "⚠ URLVoid - identified by: " + $detectedByEngines
        $Global:shouldFetchIrontPortEventsCount = $true
    } else {
        $report = "✔ URLVoid - Clean"
    }
    $report += " ( " + $sanitisedDomain + " )"
    
    return $report
}

function getSenderBaseReportForURL($URL) {
    [regex] $expression = 'leftside'
    $response =  sendGETRequest $URL
    $content = $response.content
    # $reputation = $expression.Match($content)
    $reputation = $content -like 'Neutral'
    Write-Host $Matches
    return $response
}

# getSenderBaseReportForURL("http://www.senderbase.org/lookup/?search_string=x")

processCommandLineParams $url
