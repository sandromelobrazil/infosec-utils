$keys = @('HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices')

$keys | ForEach-Object {
    reg query $_
}