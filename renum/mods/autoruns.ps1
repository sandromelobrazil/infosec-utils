param(
    [string] $user
)
$SEPARATOR = "`n_____________________________________________________________________________________________`n"

function printSeparator($messageString) {
    Write-Host $SEPARATOR [*] $messageString...`n -ForegroundColor Yellow
}

$SID = ((New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier])).value
Write-Host "[*] Retrieving registry keys for user $user (SID $SID)`n"

[array] $PATHS = (
    "HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Run\",
    "HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run\",
    "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKEY_USERS\$SID\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKEY_USERS\$SID\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    )

foreach ($path in $PATHS) {
    printSeparator "Retrieving $path"
    reg query $path
}


function getServices() {
    printSeparator "Retrieving services"
    $services = Get-ChildItem -Path HKLM:\System\CurrentControlSet\Services | ForEach-Object { 
        Get-ItemProperty $_.PsPath
    } 
    
    $services | Sort-Object -Property "ImagePath" | ForEach-Object {
        if ($_.ImagePath -notlike "*.sys" -and $_.ImagePath -ne "") {
            $_.ImagePath -replace ('"', "")
        }
    }
}

getServices
printSeparator "Retrieving scheduled tasks"
schtasks.exe

# HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
# HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
# HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
# HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
# HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
# HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
# HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
