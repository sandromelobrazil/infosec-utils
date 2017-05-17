param(
    [string] $key
)

if ($key -eq "" -or $key -eq $null) {
    $key = Read-Host -Prompt "[!] Specify the key you want to query (TIP: use -key to avoid this prompt next time)"
}

reg query $key