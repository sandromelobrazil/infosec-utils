param(
    [string] $user
)

$SID = ((New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier])).value

[array] $PATHS = (
    "REGISTRY::HKEY_USERS\$SID\",
    "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Run",
    "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "REGISTRY::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "REGISTRY::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "REGISTRY::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
    # "REGISTRY::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
    # "REGISTRY::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\\AppInit_DLLs"
    )

foreach ($path in $PATHS) {
    Get-Item $path
    Write-Host
}

# HKLM\System\CurrentControlSet\Services
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
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\\AppInit_DLLs