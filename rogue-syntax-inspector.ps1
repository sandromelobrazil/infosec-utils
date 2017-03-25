<#
    Author - mantvydas.baranauskas@usbank.com
#>

$Global:MAC_WHITELIST = "x"
$Global:MAC_BLACKLIST = "y"
$Global:MACHINE_WHITELIST = "z"
$Global:MACHINE_BLACKLIST = "d"

function main() {
    parseMACwhitelist
    parseMachineWhitelist
    parseMACblacklist
    parseMachineBlacklist
}

function parseMachineWhitelist() {
    [int] $expectedNumberOfFields = 4
    processFile $Global:MACHINE_WHITELIST $expectedNumberOfFields
}

function parseMachineBlacklist() {
    [int] $expectedNumberOfFields = 4
    processFile $Global:MACHINE_BLACKLIST $expectedNumberOfFields
}

function parseMACwhitelist() {
    [int] $expectedNumberOfFields = 5
    processFile $Global:MAC_WHITELIST $expectedNumberOfFields
}

function parseMACblacklist() {
    [int] $expectedNumberOfFields = 5
    processFile $Global:MAC_BLACKLIST $expectedNumberOfFields
}

function processFile($filePath, $expectedNumberOfFields) {
    [int] $recordCounter = 0
    [int] $emptyRecordCounter = 0
    [int] $anomalousRecordCounter = 0
   
    [string] $sanitisedFile = ""
    $fileContent = ""

    Write-Host `n`n`n`n[*] Parsing: $filePath
    $fileContent = Get-Content $filePath
    Write-Host [*] $fileContent.Length records found..
    Write-Host [*] Analysing file for anomalous records, that need to be fixed by hand..`n

    $fileContent | ForEach-Object {
        $record = $_
        $isEmptyRecord = isEmptyRecord $record $emptyRecordCounter
        $fieldsCount = hasExpectedNumberOfFields $record $expectedNumberOfFields
        
        #preparing a sanitised file by removing empty lines
        if (!$isEmptyRecord -and $recordCounter -ne $fileContent.Length - 1) {
            $sanitisedFile += $record + "`n"
        } elseif (!$isEmptyRecord -and $recordCounter -eq $fileContent.Length - 1) {
            $sanitisedFile += $record
        } else {
            $emptyRecordCounter++
        }

        if ($fieldsCount -lt $expectedNumberOfFields -and !$isEmptyRecord) {
            #subtract recordcounter - emptylinesCount
            Write-Host "Anomalous record" ($recordCounter + 1 - $emptyRecordCounter) : $record -ForegroundColor Magenta
            $anomalousRecordCounter++
        }

        $recordCounter++
    }

    Write-Host `n==============================
    Write-Host Total records: $recordCounter
    Write-Host Empty records: $emptyRecordCounter
    Write-Host Anomalous records incl. empty: $anomalousRecordCounter
    Write-Host `n[*] Overwriting sanitised file...
    $sanitisedFile | Out-File $filePath
    Write-Host [*] Completed`n -ForegroundColor Yellow
}

function hasExpectedNumberOfFields($record, [int] $expectedFields) {
    [array] $fields = $record -split ","
    return $fields.Count
}

function isEmptyRecord($record, [int] $emptyRecordCounter) {
    if ($record -eq "") {
        return $true
    }
    return $false
}

main