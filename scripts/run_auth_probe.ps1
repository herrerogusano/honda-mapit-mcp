param()

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$oldEmail = $env:MAPIT_EMAIL
$oldPassword = $env:MAPIT_PASSWORD
$oldPythonPath = $env:PYTHONPATH
$hadEmail = Test-Path Env:MAPIT_EMAIL
$hadPassword = Test-Path Env:MAPIT_PASSWORD
$hadPythonPath = Test-Path Env:PYTHONPATH
$secureEmail = $null
$securePassword = $null
$email = $null
$password = $null
$emailBstr = [IntPtr]::Zero
$passwordBstr = [IntPtr]::Zero
$exitCode = 1

try {
    $secureEmail = Read-Host "MAPIT email" -AsSecureString
    $securePassword = Read-Host "MAPIT password" -AsSecureString
    $emailBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureEmail)
    $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $email = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($emailBstr)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)

    $env:MAPIT_EMAIL = $email
    $env:MAPIT_PASSWORD = $password
    $env:PYTHONPATH = Join-Path $repoRoot "src"

    Push-Location $repoRoot
    try {
        & py "scripts\probe_auth.py"
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}
catch {
    Write-Error "Authentication probe failed before completion."
    $exitCode = 1
}
finally {
    if ($emailBstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($emailBstr)
        $emailBstr = [IntPtr]::Zero
    }
    if ($passwordBstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
        $passwordBstr = [IntPtr]::Zero
    }
    if ($secureEmail -ne $null) {
        $secureEmail.Dispose()
        $secureEmail = $null
    }
    if ($securePassword -ne $null) {
        $securePassword.Dispose()
        $securePassword = $null
    }
    $password = $null
    $email = $null

    if ($hadEmail) { $env:MAPIT_EMAIL = $oldEmail } else { Remove-Item Env:MAPIT_EMAIL -ErrorAction SilentlyContinue }
    if ($hadPassword) { $env:MAPIT_PASSWORD = $oldPassword } else { Remove-Item Env:MAPIT_PASSWORD -ErrorAction SilentlyContinue }
    if ($hadPythonPath) { $env:PYTHONPATH = $oldPythonPath } else { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
    $oldEmail = $null
    $oldPassword = $null
    $oldPythonPath = $null
}

exit $exitCode
