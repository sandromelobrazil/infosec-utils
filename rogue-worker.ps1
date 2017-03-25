Param(
    [string] $forgiveness
)

$Global:MAX_ATTEMPTS = 7
$Global:WHITELIST_BLACKLIST_PAYLOAD = ""

if ($forgiveness -ne "") {
    $Global:MAX_ATTEMPTS = $forgiveness
}

function setupPathsToDataSources() {
    $prompt = "Specify absolute path to a folder containing all required files"
    $directoryLocation = Read-Host -Prompt $prompt
    # $directoryLocation = "C:\"
    
    if ($directoryLocation -ne "" -and $directoryLocation -like "*C:\*") {
        $Global:FILTERED_DEVICES = $directoryLocation + "\*.csv"
        $Global:MAC_WHITELIST = $directoryLocation + "\.txt"
        $Global:MAC_BLACKLIST = $directoryLocation + "\.txt"
        $Global:MACHINE_NAME_WHITELIST = $directoryLocation + "\.txt"
        $Global:MACHINE_NAME_BLACKLIST = $directoryLocation + "\.txt"
    } else {
        Write-Host $prompt
        setupPathsToDataSources
    }
}

function main() {
    setupPathsToDataSources
    [array] $filteredDevices = ConvertFrom-Csv (Get-Content $Global:FILTERED_DEVICES)
    Write-Host "[*] Reading filtered devices list..."
    processFilteredDevices $filteredDevices
    printPotentialPayload
}

function processFilteredDevices($filteredDevices) {
    [int] $index = 1
    [int] $devicesCount = $filteredDevices.Length

    if ($devicesCount -gt 0) {
        $filteredDevices.ForEach({
            $filteredDevice = $_
            Write-Host "`n`n[ $index/$devicesCount ] Processing filtered device:" $filteredDevice.infoblox_MachineName -ForegroundColor Cyan
            findSimilarDevices $filteredDevice $Global:MACHINE_NAME_WHITELIST   
            findSimilarDevices $filteredDevice $Global:MAC_WHITELIST   
            findSimilarDevices $filteredDevice $Global:MAC_BLACKLIST   
            findSimilarDevices $filteredDevice $Global:MACHINE_NAME_BLACKLIST
            $index++
        })
    } else {
        Write-Host "[*] No filtered devices found..."
    }
}

function printPotentialPayload() {
    if ($Global:WHITELIST_BLACKLIST_PAYLOAD -ne "") {
        Write-Host `n`n[*] Consider the below payload to submit to Rogue Device Parser script on CSIRT tools website.. -ForegroundColor Yellow 
        Write-Host [*] Amend the notes/description field with the most accurate description in case the automated one does not fit..`n
        $Global:WHITELIST_BLACKLIST_PAYLOAD
    } else {
        Write-Host "`n[*] Final result: no devices to whitelist or blacklist with parameter -forgiveness $Global:MAX_ATTEMPTS. `n[*] Try re-running the script with an increased -forgiveness value.`n"        
    }
}

function determineConsoleColour($knownDevicesFile) {
    if ($knownDevicesFile -like "*white*") {
        return "Green"                    
    } else {
        return "Red"
    }
}

function constructWhitelistBlacklistPayload($filteredDevice, $knownDevicesFile, $knownDevice) {
    $MACAddress = $filteredDevice.infoblox_MAC

    if ($Global:WHITELIST_BLACKLIST_PAYLOAD -notlike "*" + $MACAddress + "*") {
        if ($knownDevicesFile -like "*black*") {
            $action = "B"
        } else {
            $action = "W"
        }
        $suggestedNotes = getPersonalNotesFromKnownDeviceEntry $knownDevice
        $Global:WHITELIST_BLACKLIST_PAYLOAD += $env:USERNAME + ",$action" + "," + $filteredDevice.infoblox_MachineName + "," + $MACAddress + "," + $filteredDevice.ieee_NicCreator + ",$suggestedNotes`n`r"
    }
}

function getPersonalNotesFromKnownDeviceEntry($knownDevice) {
    $splitResult = $knownDevice -split "Personal Notes: "
    
    if ($splitResult.Length -gt 1) {
        $splitResult = $splitResult[1] -split ","
        $suggestedNotes = $splitResult[0] -replace ('"',"")
    } else {
        $suggestedNotes = "[!] Dear analyst, please add the device description"
    }
    return $suggestedNotes
}

function findSimilarDevices($filteredDevice, $knownDevicesFile) {
    [int] $attempt = 0
    $isSimilarDeviceFound = $false
    $filteredDeviceName = $filteredDevice.infoblox_MachineName

    Get-Content $knownDevicesFile | ForEach-Object {
        $knownDevice = $_

        while ($attempt -le $Global:MAX_ATTEMPTS) {
            $attemptName = $filteredDeviceName.Substring(0, $filteredDeviceName.Length - $attempt)
            $isSimilar = $knownDevice -like "*"+$attemptName+"*"
            
            if ($isSimilar -eq $true -and !$isSimilarDeviceFound) {
                Write-Host "[*] Found similar device": $knownDevice -ForegroundColor (determineConsoleColour $knownDevicesFile)
                Write-Host "[*] Similar because of:" $attemptName`n[*] Found in: (Split-Path -Leaf $knownDevicesFile)`n
                constructWhitelistBlacklistPayload $filteredDevice $knownDevicesFile $knownDevice
                $isSimilarDeviceFound = $true
                break    
            }
            $attempt++
        }
        $attempt = 0
    }
}

main