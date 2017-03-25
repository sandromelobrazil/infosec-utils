. "C:\ad-authentication.ps1"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$Global:SPLUNK_BASE_URL = "https://x/services/search/jobs/export"

function fetchLogsForSplunkSearchQuery($searchQuery) {
    $requestParameters = @{
        search = "search " + $searchQuery
        output_mode = "csv"
    }
    
    $response = invokeSplunkRequest $requestParameters 
    $logsList = ConvertFrom-Csv $response
    
    return $logsList
}

function invokeSplunkRequest($requestParameters) {
    $credentials = getCredentials
    $response = Invoke-WebRequest -Uri $Global:SPLUNK_BASE_URL -Method POST -Credential $credentials -Body $requestParameters
    return $response
}

