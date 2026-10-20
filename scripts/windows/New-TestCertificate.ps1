# Ephemeral CI-only development certificate: NEVER used for a public release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:CI -or -not $env:GITHUB_ACTIONS) { throw 'Only permitted inside disposable GitHub CI runners.' }
Write-Host 'Creating non-exportable temporary CodeSigningCert on Windows software key provider.'
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=BootNexa CI TEST ONLY' -KeyAlgorithm RSA -KeyLength 2048 -Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy NonExportable -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(1)
Write-Host 'Temporary signing cert created; no trust-store modifications are performed.'
# An ephemeral CI-only signer is deliberately NOT added to Windows Trusted Root.
# Test mode checks identity and detects corrupted signatures. Only Production
# verifies a public chain and trusted RFC 3161 timestamp.
if (-not $env:GITHUB_ENV) { throw 'GITHUB_ENV not available' }
"BOOTNEXA_SIGNER_THUMBPRINT=$($cert.Thumbprint)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
Write-Host 'Ephemeral TEST ONLY signing identity ready.'
