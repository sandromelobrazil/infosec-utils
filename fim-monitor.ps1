# this is an array, so use commas to separate monitored folders 
[array] $Global:MONITORED_FOLDERS = 
    "C:\",
    "C:\Windows\System32\config\"

$Global:FIM_SAVE_LOCATION = "C:\Users\$env:USERNAME\Downloads\"
$Global:FIM_BASELINE = $Global:FIM_SAVE_LOCATION + "fim-baseline.txt"

function main () {
    Write-Host `n`n`n
    $isBaslineReport = $false
    $monitoredFiles = getAllMonitoredFiles
    $monitoredFilesWithHashes = addHashesToMonitoredFiles $monitoredFiles
    $monitoredFilesReport = generateMonitoredFilesReport $monitoredFilesWithHashes

    if (!(isBaselineFIMFound)) {
        $isBaslineReport = $true
    }
    
    $reportFilePath = saveMonitoredFilesReport $monitoredFilesReport $isBaslineReport
    compareReportWithBaseline $reportFilePath
}

function compareReportWithBaseline($reportFilePath) {
    $baselineReport = Get-Content $Global:FIM_BASELINE
    $currentReport = Get-Content $reportFilePath
    [array] $differences = Compare-Object -ReferenceObject $baselineReport -DifferenceObject $currentReport 

    Write-Host "[*] Comparing baseline report with the current report..`n"
    
    if ($differences -ne $null) {
        Write-Host "[*] Changes detected - new, modified or missing files:" -ForegroundColor Red
        
        $differences.forEach({
            if ($_.SideIndicator -eq "=>") {
                $explanation = "=> deviation from baseline"
            } else {
                $explanation = "<= deviation from report"
            }
            Write-Host $explanation - $_.InputObject
        })
    } else {
        Write-Host [*] No changes to monitored files detected so far.. -ForegroundColor Green
    }
}

function saveMonitoredFilesReport($monitoredFilesReport, [bool] $isBaselineReport) {
    if ($isBaselineReport) {
        $filePath = $Global:FIM_BASELINE
    } else {
        $filePath = $Global:FIM_SAVE_LOCATION + "fim-report-" + (Get-Date).ToString("dd-MM-yyyy_HHmmss") + ".txt"
    }
    Out-File -InputObject $monitoredFilesReport -FilePath $filePath
    
    return $filePath
}

function generateMonitoredFilesReport($monitoredFilesWithHashes) {
    $content
    Write-Host [*] Generating report for monitored files..`n

    $monitoredFilesWithHashes.ForEach({
        $objectType = $_.GetType()

        if ($objectType.Name -ne "Int32") {
            $hash = $_.hash.Hash
            
            if ($hash -ne $null) {
                $line = $hash + " " + $_.file.FullName + "`r`n"
                $content += $line
            }
        }
    })

    return $content
}

function getMD5ForFile($fileName) {
    $hash = Get-FileHash $fileName -Algorithm MD5
    
    return $hash
}

function addHashesToMonitoredFiles([array] $monitoredFiles) {
    [System.Collections.ArrayList] $monitoredFilesHashes = @()
    Write-Host [*] Calculating hashes for monitored files..`n
    
    $monitoredFiles.ForEach({
        $objectType = $_.GetType()
        
        if ($objectType.Name -ne "Int32") {
            $hash = getMD5ForFile $_.FullName
            $updatedFileObject = (updateMonitoredFileObject $_ $hash)
            $monitoredFilesHashes.Add($updatedFileObject)
        }
    })

    return $monitoredFilesHashes
}

function updateMonitoredFileObject($fileObject, $hash) {
    $updatedFile = @{
        file = $fileObject
        hash = $hash
    }

    return $updatedFile
}

function getAllMonitoredFiles() {
    [System.Collections.ArrayList] $filesList = @()

    $Global:MONITORED_FOLDERS.forEach({
        [array] $files = Get-ChildItem $_ -Recurse
        Write-Host [*] Finding all the files in $_ ..`n
        
        $files.ForEach({
            $filesList.Add($_)
        })
    })

    return $filesList
}

function isBaselineFIMFound() {
    $isBaselineFound = Test-Path -Path $Global:FIM_BASELINE
    
    if ($isBaselineFound) {
        Write-Host "[*] FIM baseline file found..`n"
        return $true
    } else {
        Write-Host "[*] FIM baseline file not found.. Creating one now..`n"
        return $false
    }
}

main