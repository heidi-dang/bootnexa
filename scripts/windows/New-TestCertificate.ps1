# Ephemeral CI-only development certificate: NEVER used for a public release.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:CI -or -not $env:GITHUB_ACTIONS) { throw 'Only permitted inside disposable GitHub CI runners.' }
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=BootNexa CI TEST ONLY' -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy NonExportable -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(1)
$path = Join-Path $env:RUNNER_TEMP 'bootnexa-ci-test.cer'
Export-Certificate -Cert $cert -FilePath $path | Out-Null
# Trust exists only inside the disposable CI VM. No key or PFX is exported.
Import-Certificate -FilePath $path -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
Import-Certificate -FilePath $path -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher' | Out-Null
if (-not $env:GITHUB_ENV) { throw 'GITHUB_ENV not available' }
"BOOTNEXA_SIGNER_THUMBPRINT=$($cert.Thumbprint)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
Write-Host 'Ephemeral TEST ONLY signing identity ready.'
