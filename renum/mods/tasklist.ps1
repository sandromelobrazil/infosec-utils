$Global:RUNNING_PROCESSES
[array] $Global:KEY_PROCESSES = @(
    @{name="smss"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="csrss"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="services"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="svchost"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="winlogon"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="lsm"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="lsass"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="taskhost"; expectedPath="$env:SystemRoot\system32\"}, 
    @{name="wininit"; expectedPath="$env:SystemRoot\system32\"},
    @{name="explorer"; expectedPath="$env:windir\"} )

Write-Host [*] Retrieving running processes... -ForegroundColor Yellow
tasklist /SVC | sort

function getProcessImagePath() {
    Write-Host `n`n[*] Retrieving image paths for running processes... -ForegroundColor Yellow
    $processes = Get-Process
    $Global:RUNNING_PROCESSES = $processes
    $processes | Sort-Object -Property Path | Format-Table Path,ProcessName -AutoSize
}

function isProcessesInExpectedLocation($runningProcess) {
    foreach ($keyProcess in $Global:KEY_PROCESSES) {
        $processImageName = $keyProcess.name + ".exe"
        $expectedPath = $keyProcess.expectedPath + $processImageName
        
        if ($runningProcess.ProcessName -like $keyProcess.name -and $runningProcess.ProcessName -notlike "iexplore") {
            if ($runningProcess.Path -like $expectedPath) {
                printFileInExpectedLocation $processImageName $expectedPath
            } else {
                printFileInUnExpectedLocation $processImageName $runningProcess $expectedPath
            }
        } 
    }
}

function printFileInExpectedLocation($processImageName, $expectedPath) {
    Write-Host [+] $processImageName "`t" $expectedPath - as expected
}

function printFileInUnExpectedLocation($processImageName, $runningProcess, $expectedPath) {
    Write-Host [!] $processImageName "`t" $runningProcess.Path - $expectedPath expected. -ForegroundColor Red
}

function isIEInExpectedLocation($runningProcess) {
    $iexplore = "iexplore.exe"
    if ($runningProcess.Path -like "*$iexplore*") {
        $expectedPath1 = ("C:\Program Files\Internet Explorer\$iexplore")
        $expectedPath2 = ("C:\Program Files (x86)\Internet Explorer\$iexplore")
        if ($runningProcess.Path -like $expectedPath1 -or $runningProcess.Path -like $expectedPath2) {
            printFileInExpectedLocation $iexplore "C:\Program Files*\Internet Explorer"
        } else {
            printFileInUnExpectedLocation $iexplore $runningProcess "C:\Program Files*\Internet Explorer"
        }
    }
}

function isRunningFromTempFolder($runningProcess) {
    if ($runningProcess.Path -like "$env:TEMP\*.exe" -or $runningProcess.Path -like "$env:SystemRoot\temp\*.exe" -or $runningProcess.Path -like "$env:USERNAME\*.exe" -or $runningProcess.Path -like "C:\temp\*.exe") {
        Write-Host [!] Suspicious executable location: $runningProcess.Path -ForegroundColor Red
    }
}

function scanProcessesForSuspiciousness() {
    Write-Host [*] Checking if critical Windows procceses are loaded from expected locations... -ForegroundColor Yellow
    foreach ($runningProcess in $Global:RUNNING_PROCESSES) {
        isProcessesInExpectedLocation $runningProcess
        isIEInExpectedLocation $runningProcess
        isRunningFromTempFolder $runningProcess
    }
}

getProcessImagePath
scanProcessesForSuspiciousness
