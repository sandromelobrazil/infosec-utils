$Global:RUNNING_PROCESSES
$Global:KEY_PROCESSES = @("smss", "csrss", "services", "svchost", "winlogon", "lsm", "lsass", "taskhost", "winit", "os")

Write-Host [*] Retrieving running processes... -ForegroundColor Yellow
tasklist /SVC | sort

function getProcessImagePath() {
    Write-Host `n`n[*] Retrieving image paths for running processes... -ForegroundColor Yellow
    $processes = Get-Process
    $Global:RUNNING_PROCESSES = $processes
    $processes | Sort-Object -Property Path | Format-Table Path,ProcessName -AutoSize
}

function areKeyProcessesInExpectedLocations() {
    Write-Host [*] Checking if key Windows procceses are loaded from expected locations... -ForegroundColor Yellow
    $explorer = "explorer.exe"
    
    foreach ($keyProcess in $Global:KEY_PROCESSES) {
        $keyProcess = $keyProcess + ".exe"
        foreach ($runningProcess in $Global:RUNNING_PROCESSES) {
            if ($runningProcess.Path -like "*$keyProcess*") {
                $expectedPath = "$env:SystemRoot\system32\$keyProcess"
                
                if ($runningProcess.Path.ToLower() -like $expectedPath) {
                    Write-Host [+] $keyProcess is in $expectedPath as expected
                } else {
                    Write-Host [!] $keyProcess is in $runningProcess.Path - $expectedPath expected. -ForegroundColor Red
                }

            }

            # if ($runningProcess.Path -like "*$explorer") {
            #     $expectedPath = ("$env:SystemRoot\$explorer").ToLower()
            #     if ($runningProcess.Path -like $expectedPath) {
            #         Write-Host [+] $explorer is in $expectedPath as expected
            #     } else {
            #         Write-Host [!] $explorer is in $runningProcess.Path - $expectedPath expected. -ForegroundColor Red
            #     }
            # }
        }
    }
}

getProcessImagePath
areKeyProcessesInExpectedLocations $runningProcesses
