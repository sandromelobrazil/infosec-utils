param(
    [string] $user
)

$SID = ((New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier])).value

[array] $PATHS = (
    "REGISTRY::HKEY_USERS\$SID\Software\Microsoft\Internet Explorer\TypedURLs"
    )

foreach ($path in $PATHS) {
    Get-Item $path
}
