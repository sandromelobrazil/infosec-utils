Write-Host [*] Retrieving running processes... -ForegroundColor Yellow
tasklist /SVC | sort

function getProcessImagePath() {
    Write-Host `n`n[*] Retrieving image paths for running processes... -ForegroundColor Yellow
    Get-Process  | Sort-Object -Property "Path" | Format-Table Path, ProcessName -AutoSize 
}

getProcessImagePath
