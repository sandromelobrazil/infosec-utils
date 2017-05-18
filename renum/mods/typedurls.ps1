param(
    [string] $user
)

$SID = ((New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier])).value

[array] $PATHS = (
    "HKEY_USERS\$SID\Software\Microsoft\Internet Explorer\TypedURLs"
    )

foreach ($path in $PATHS) {
    reg query $path
}
