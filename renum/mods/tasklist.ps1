$Global:RUNNING_PROCESSES
$Global:KEY_PROCESSES = @("smss", "csrss", "services", "svchost", "winlogon", "lsm", "lsass", "taskhost", "wininit")

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
        $keyProcess = $keyProcess + ".exe"
        $expectedPath = "$env:SystemRoot\system32\$keyProcess"
        if ($runningProcess.Path -like "*$keyProcess*") {
            if ($runningProcess.Path.ToLower() -like $expectedPath) {
                Write-Host [+] $keyProcess "`t" $expectedPath - as expected
            } else {
                Write-Host [!] $keyProcess "`t" $runningProcess.Path - $expectedPath expected. -ForegroundColor Red
            }
        }
    }
}

function isExplorerInExpectedLocation($runningProcess) {
    $explorer = "explorer.exe"
    if ($runningProcess.Path -like "*$explorer*") {
        $expectedPath = ("$env:windir\$explorer").ToLower()
        if ($runningProcess.Path -like $expectedPath) {
            Write-Host [+] $explorer "`t" $expectedPath as expected
        } else {
            Write-Host [!] $explorer "`t" $runningProcess.Path - $expectedPath expected. -ForegroundColor Red
        }
    }
}

function isRunningFromTempFolder($runningProcess) {
    if ($runningProcess.Path -like "$env:TEMP\*.exe" -or $runningProcess.Path -like "$env:SystemRoot\temp\*.exe" -or $runningProcess.Path -like "$env:USERNAME\*.exe") {
        Write-Host [!] Suspicious executable location: $runningProcess.Path -ForegroundColor Red
    }
}

function scanProcessesForSuspiciousness() {
    Write-Host [*] Checking if critical Windows procceses are loaded from expected locations... -ForegroundColor Yellow
    foreach ($runningProcess in $Global:RUNNING_PROCESSES) {
        isProcessesInExpectedLocation $runningProcess
        isRunningFromTempFolder $runningProcess
        isExplorerInExpectedLocation $runningProcess
    }
}

getProcessImagePath
scanProcessesForSuspiciousness
