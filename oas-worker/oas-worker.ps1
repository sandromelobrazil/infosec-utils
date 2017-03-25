Param(
    [string] $folder
)
$Global:PATH_TO_CSV = "C:\"
$Global:OAS_FILE_NAME = "\xxx.csv"
$Global:TIME_FORMAT = "MM/dd/yyyy:HH:mm:ss"
$Global:TIME_FORMAT_FFF = "yyyy-MM-dd HH:mm:ss.fff"
$Global:EVENT_SEPARATOR = "############################################"
. "C:\Users\x\url-checker.ps1"
. "C:\Users\x\splunk.ps1"

function openCSV() {    
    if ($folder -ne "") {
        $Global:PATH_TO_CSV = $folder
    } else {
        $Global:PATH_TO_CSV = Read-Host -Prompt "Enter folder containing OAS report csv file"
    }
    
    $Global:PATH_TO_CSV += $Global:OAS_FILE_NAME
    $csvFile = Import-Csv $Global:PATH_TO_CSV

    return $csvFile
}

function generateSplunkSearchQueryFromThreatAttributes($OASevent) {
    $eventTime = [datetime] $OASevent."Event Generated Time"
    $targetIP = $OASevent."Threat Target IPv4 Address"
    $startTime = $eventTime.AddSeconds(-12).ToString($TIME_FORMAT)
    $endTime = $eventTime.ToString($TIME_FORMAT)
    $splunkSearchQuery = "starttime=" + [string] $startTime + " endtime=" + [string] $endTime + " " + $targetIP
    return $splunkSearchQuery
}

function processthreatEventsCsv($threatEventsCsv) {
    [int] $eventIndex = 1
    $threatEventsCsv.ForEach({
        $threatEvent = $_
        $splunkSearchQuery = generateSplunkSearchQueryFromThreatAttributes $threatEvent
        $maliciousAttributes = extractMaliciousFileNameAndFolderFromThreatEvent $threatEvent
        $logsList = fetchLogsForSplunkSearchQuery $splunkSearchQuery
        insertAdditionalColumnsToReportHeader $threatEvent $splunkSearchQuery
        processThreatEventLogs $logsList $threatEventsCsv $threatEvent $maliciousAttributes $eventIndex
        $eventIndex++
    })
}

function processThreatEventLogs([array] $logsList, $threatEventsCsv, $threatEvent, $maliciousAttributes, $eventIndex) {
    $closestMatchingRequest = $null
    $threatFilePath = $threatEvent."Threat Target File Path"
    [int] $logIndex = 0
    $eventTimes = $null
    $totalEvents = $threatEventsCsv.length
    $maliciousURL = $null
    $threatFindings = @{
        maliciousURL = $results.maliciousURL
        WBRS = $results.WBRS
        Notes = $results.Notes
        virusTotal = ""
        urlVoid = ""
        ironPort = ""
        senderBase = ""
    }

    Write-Host $Global:EVENT_SEPARATOR `n
    Write-Host "🔎 [ $eventIndex/$totalEvents ] searching evidence for threat:" -ForegroundColor DarkCyan
    Write-Host $threatFilePath`n -ForegroundColor DarkCyan
    
    if ($logsList -ne $null) {
        
        $logsList.ForEach({
            $logItem = $_           
            $rawLogData = $logItem."_raw"          
            $eventTimes = extractEventTimes $threatEvent $logItem         
            $hasMaliciousAttributes = hasMaliciousAttributeInLogData $rawLogData $maliciousAttributes
            
            if ($hasMaliciousAttributes.isMalicious -and $closestMatchingRequest -eq $null) {
                $closestMatchingRequest = $logsList[$logIndex]
                Write-Host $hasMaliciousAttributes.message -ForegroundColor DarkYellow
            }
            $logIndex++
        })

        # sometimes we can't find logs in splunk for a direct request to the malicious resource. In those cases, we're making a guess and suggesting that the closest request time-wise to the original threat time is the one to blame.
        # the closest request will be the first one in the $logsList as they come sorted Z-A
        if ($closestMatchingRequest -eq $null -and !$hasMaliciousAttributes.isMalicious) {
            $closestMatchingRequest = $logsList[0]
            Write-Host "No direct malicious request found. Closest request to the threat time:" -ForegroundColor White
        }
        
        fillinThreatFindings $threatFindings $closestMatchingRequest
        printRequestDetails $closestMatchingRequest $eventTimes $threatFindings
        $eventIndex++

    } else {
        handleNoLogs $logsList $threatEvent $threatFindings
    }

    updateThreatEventWithFindings $threatEvent $threatFindings
    Write-Host $Global:EVENT_SEPARATOR `n`n`n
}

function fillinThreatFindings($threatFindings, $closestMatchingRequest) {
    $WBRS = extractWBRS $closestMatchingRequest
    $sanitisedURL = (extractMaliciousURL $closestMatchingRequest).sanitisedURL
    $threatFindings.WBRS = $WBRS
    $threatFindings.maliciousURL = $sanitisedURL
}

function handleNoLogs($logsList, $threatEvent, $threatFindings) {
    $threatEventNotes = isPEMorJustNoLogsFound $logsList $threatEvent
    if ($threatEventNotes -ne $null) {
        Write-Host $threatEventNotes
        $threatFindings.Notes = $threatEventNotes
    }
}

function printURLReport($maliciousURL, $threatFindings) {
    $URLReport = getAllReportsForURL $maliciousURL $Global:CREDENTIALS.UserName
    $threatFindings.virusTotal = $URLReport.virusTotal
    $threatFindings.urlVoid = [string] $URLReport.urlVoid
    $threatFindings.ironPort = $URLReport.ironPort
    Write-Host $URLReport.urlVoid
    Write-Host $URLReport.virusTotal 
    Write-Host $URLReport.ironPort `n
}

function updateThreatEventWithFindings($threatEvent, $threatFindings) {
    # object used to populate the OAS report;
    $threatEvent."Notes" = $threatFindings.Notes
    $threatEvent."WBRS" = $threatFindings.WBRS
    $threatEvent."URL/Domain" = $threatFindings.maliciousURL
    $threatEvent."SenderBase" = $threatFindings.senderBase
    $threatEvent."IronPort" = $threatFindings.ironPort
    $threatEvent."VirusTotal" = $threatFindings.virusTotal
    $threatEvent."URLVoid" = $threatFindings.urlVoid
}

function isPEMorJustNoLogsFound($rawLogData, $threatEvent) {
    $threatFilePath = $threatEvent."Threat Target File Path"
    $hostName = $threatEvent."Threat Target Host Name"
    $hostIP = $threatEvent."Threat Target IPv4 Address"

    if ($threatFilePath -like '*D:\*' -or $threatFilePath -like '*autorun*') {
        $result = "Seems to be Portable Electronic Media (PEM) related. I have reminded the user this is against Acceptable Use Policies.`n"
    } elseif ($rawLogData -eq $null) {
        $result = "Could not find correlating logs in Splunk."
    } elseif ($rawLogData -eq $null -or $hostName -like '*WN-*' -and $hostIP -like '192.*') {
        $result = "Could not find correlating logs in splunk.`nThe user may have been using his notebook whilst not VPN'ed to USBank's network."
    }

    return $result    
}

function printRequestDetails($closestMatchingRequest, $times, $threatFindings) {
    $maliciousURL = (extractMaliciousURL $closestMatchingRequest).originalURL
    Write-Host "🔗 URL:" $maliciousURL
    Write-Host "WBRS:" (extractWBRS $closestMatchingRequest)
    Write-Host "🕒 Threat Time:      " $times.threatEventTimeStr
    Write-Host "🕒 HTTP Request Time:"      $times.logItemTimeStr `n
    Write-Host "RAW:" $closestMatchingRequest `n
    printURLReport $maliciousURL $threatFindings
}

function getTimeDeltaBetweenEventAndlogItem($threatEventTime, $logItemTime) {
    $delta = $threatEventTime - $logItemTime
    return [System.Math]::Abs($delta.TotalMilliseconds)
}

function extractEventTimes($threatEvent, $logItemData) {
    $threatEventTime = [datetime] $threatEvent."Event Generated Time" 
    $logItemTime = $logItemData."_time" -replace("CST|CDT", "")
    $logItemTime = [datetime] $logItemTime

    $times = @{
        threatEventTime = $threatEventTime
        threatEventTimeStr = $threatEventTime.ToString($Global:TIME_FORMAT_FFF)
        logItemTime = $logItemTime
        logItemTimeStr = $logItemTime.ToString($Global:TIME_FORMAT_FFF)
    }

    return $times
}

function hasMaliciousAttributeInLogData ($rawLogData, $maliciousAttributes) {
    $URL = (extractMaliciousURL $rawLogData).originalURL
    if ($URL -like '*' + $maliciousAttributes.maliciousFileName + '*' -and $maliciousAttributes.maliciousFileName.length -gt 4) {
        $suspicionMessage = '[✋] Found suspicious request containing a file name ' + "[" + $maliciousAttributes.maliciousFileName + "]"
        $hasMaliciousAttribute = $true
    } elseif ($URL -like '*' + $maliciousAttributes.maliciousFolderName + '*' -and $maliciousAttributes.maliciousFolderName.length -gt 4) {
        $suspicionMessage = '[✋] Found suspicious request containing a folder name ' +  "[" + $maliciousAttributes.maliciousFolderName + "]"
        $hasMaliciousAttribute = $true
    } else {
       $hasMaliciousAttribute = $false
    }

    $result = @{
        isMalicious = $hasMaliciousAttribute
        message = $suspicionMessage
    }

    return $result
}

function extractWBRS($rawLogData) {
    # will return something like this "<IW_adv,3.8", then we can split it by ',' and take the value from the right hand side
    $WBRS = $rawLogData -match '(<\w{2,},)(-?[0-9].[0-9]|ns)'
    $WBRS = $Matches[0] -split(",")
    return $WBRS[1]
}

function extractMaliciousURL($rawlogData) {
    $rawURL = $rawlogData -match '(https?:\/\/.\S+)'
    if ($rawURL) {
        $URL = $Matches[0] -split '(https?://|https?%3A%2F%2F)'

        if ($URL[4] -ne $null) {
            $URL = $URL[3] + $URL[4]
        } else {
            $URL = $URL[1] + $URL[2]
        }

        $sanitised = sanitiseURL $URL

        $URLList = @{
            originalURL = $URL
            sanitisedURL = $sanitised
        }

        return $URLList
    }
}

function extractMaliciousFileNameAndFolderFromThreatEvent($threatEvent) {
    $filePath = $threatEvent."Threat Target File Path"
    $fileName = Split-Path $filePath -Leaf 
    $fileName = sanitiseFileAndFolderNames $fileName

    $folderName = Split-Path -Path $filePath 
    $folderName = Split-Path $folderName -Leaf
    $folderName = sanitiseFileAndFolderNames $folderName
    
    return @{
        maliciousFileName = $fileName 
        maliciousFolderName = $folderName
    }
}

function sanitiseFileAndFolderNames($stringToSanitise) {
    return $stringToSanitise -creplace("(\[[0-9]\])(.[a-z0-9]{2,})", "")
}

function insertAdditionalColumnsToReportHeader($threatEvent, $splunkSearchQuery) {
    $properties = @{
        "Splunk Search Query" = "";
        "URL/Domain" = "";
        "WBRS" = "";
        "Notes" = "";
        "VirusTotal" = "";
        "URLVoid" = "";
        "IronPort" = "";
        "SenderBase" = "";
    }

    complementThreatEventWithAttribute $threatEvent "Splunk Search Query" $splunkSearchQuery
    complementThreatEventWithAttribute $threatEvent "URL/Domain" ""
    complementThreatEventWithAttribute $threatEvent "WBRS" ""
    complementThreatEventWithAttribute $threatEvent "Notes" ""
    complementThreatEventWithAttribute $threatEvent "VirusTotal" ""
    complementThreatEventWithAttribute $threatEvent "URLVoid" ""
    complementThreatEventWithAttribute $threatEvent "IronPort" ""
    complementThreatEventWithAttribute $threatEvent "SenderBase" ""
}

function complementThreatEventWithAttribute($threatEvent, $attribute, $value) {
    $threatEvent | Add-Member NoteProperty $attribute($value)
}

function saveAsNewFile() {
    $location = $Global:PATH_TO_CSV -replace (".csv", " - worked.csv")
    return $location
}

function main() {
    $threatEventsCsv = openCSV
    processthreatEventsCsv($threatEventsCsv)
    $threatEventsCsv | Export-Csv -LiteralPath (saveAsNewFile)
}

main