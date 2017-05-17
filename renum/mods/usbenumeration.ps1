param([string]$user)

$keys = @(
'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR',    
'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\USBSTOR', 
'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Enum\USBSTOR')

$keys | ForEach-Object {
    reg query $_
}