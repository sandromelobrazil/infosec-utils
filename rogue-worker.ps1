Param(
    [string] $forgiveness,
    # -hostname can be used when you want to check if we've had historical similarly named devices in whitelists or blacklists
    [string] $hostname 
)
$Global:MAX_ATTEMPTS = 7
$Global:WHITELIST_BLACKLIST_PAYLOAD = ""

function processArguments() {
    if ($forgiveness -ne "") {
        $Global:MAX_ATTEMPTS = $forgiveness
    }
    if ($hostname -ne "") {
        checkDeviceByHostname $hostname
    }
}

function setupPathsToDataSources() {
    # $prompt = "Specify absolute path to a folder containing filteredResultSetWithEnrichedDataPrimoColumns* and all whitelist/blacklist files"
    # $directoryLocation = Read-Host -Prompt $prompt
    $directoryLocation = "C:\Users\$env:USERNAME\Desktop\Rogue"
    
    if ($directoryLocation -ne "" -and $directoryLocation -like "*C:\*") {
        $Global:FILTERED_DEVICES = $directoryLocation + "\filteredResultSetWithEnrichedDataPrimoColumns_*.csv"
        $Global:MAC_WHITELIST = $directoryLocation + "\mac_address_white_list.txt"
        $Global:MAC_BLACKLIST = $directoryLocation + "\mac_address_black_list.txt"
        $Global:MACHINE_NAME_WHITELIST = $directoryLocation + "\machine_name_white_list.txt"
        $Global:MACHINE_NAME_BLACKLIST = $directoryLocation + "\machine_name_black_list.txt"
    } else {
        Write-Host $prompt
        setupPathsToDataSources
    }
}

function main() {
    setupPathsToDataSources
    processArguments
    [array] $filteredDevices = ConvertFrom-Csv (Get-Content $Global:FILTERED_DEVICES)

    # if the -hostname is not provided, the script will process the filtered devices .csv file.
    if ($hostname -eq "") {
        Write-Host "[*] Reading filtered devices list..."
        $containsSimilarDevices = processFilteredDevices $filteredDevices
        printPotentialPayload
    }
}

function processFilteredDevices($filteredDevices) {
    [int] $index = 1
    [int] $devicesCount = $filteredDevices.Length
    $isSimilarDeviceFound = $false
    [array] $filesToCheck = @($Global:MACHINE_NAME_WHITELIST, $Global:MAC_WHITELIST, $Global:MAC_BLACKLIST, $Global:MACHINE_NAME_BLACKLIST)

    if ($devicesCount -gt 0) {
        $filteredDevices.ForEach({
            $filteredDevice = $_
            Write-Host "`n`n[ $index/$devicesCount ] Processing filtered device:" $filteredDevice.infoblox_MachineName -ForegroundColor Cyan
            
            foreach($file in $filesToCheck) {
                $constainsSimilar = findSimilarDevices $filteredDevice $file
                if ($isSimilarDeviceFound -eq $false -and $constainsSimilar -eq $true) {
                    $isSimilarDeviceFound = $true
                }
            }
            $index++
        })
    } else {
        Write-Host "[*] No filtered devices found..."
    }
    
    return $isSimilarDeviceFound
}

function checkDeviceByHostname($hostname) {
    [array] $device = @{
        infoblox_MachineName = $hostname
    }
    $isSimilarDeviceFound = processFilteredDevices $device    

    if (!$isSimilarDeviceFound) {
        Write-Host `n[*] No similar devices found...
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
    [int] $iteration = 0
    [int] $percentComplete = 0
    $isSimilarDeviceFound = $false
    $filteredDeviceName = $filteredDevice.infoblox_MachineName
    $knownDevicesFileContent =  Get-Content $knownDevicesFile
    $knownDevicesCount = $knownDevicesFileContent.Length
    $activity = "Finding similar devices, please wait..."
    $progress = "Devices processed:"

    $knownDevicesFileContent | ForEach-Object {
        $knownDevice = $_
        $percentComplete = $iteration / $knownDevicesCount * 100

        # $filteredDeviceName.Length -gt $attempt + 4 <- this is so that similarly named device contains at least 4 similar characters, otherwise it's considered that no similar device is found.
        while ($attempt -lt $Global:MAX_ATTEMPTS -and $filteredDeviceName.Length -gt $attempt + 4) {
            $attemptName = $filteredDeviceName.Substring(0, $filteredDeviceName.Length - $attempt)
            $isSimilar = $knownDevice -like "*"+$attemptName+"*"
            
            if ($isSimilar -eq $true -and !$isSimilarDeviceFound) {
                Write-Host "[*] Found similar device": $knownDevice -ForegroundColor (determineConsoleColour $knownDevicesFile)
                Write-Host "[*] Similar because of:" $attemptName`n[*] Found in: (Split-Path -Leaf $knownDevicesFile)`n
                constructWhitelistBlacklistPayload $filteredDevice $knownDevicesFile $knownDevice
                $isSimilarDeviceFound = $true
                updateProgress $activity $progress $percentComplete
                break    
            }
            $attempt++
        }
        $iteration++
        $attempt = 0
    }
    updateProgress $activity $progress $percentComplete    

    return $isSimilarDeviceFound
}

function updateProgress($activity, $progress, $percentComplete) {
    Write-Progress -Activity $activity -Status $progress -PercentComplete $percentComplete 
}

main
