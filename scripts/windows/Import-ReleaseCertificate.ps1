# Fail-closed PKCS#12 import for a protected, manual GitHub production environment.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:CI -or -not $env:GITHUB_ACTIONS) { throw 'Only supported in a protected CI release job.' }
if ([string]::IsNullOrWhiteSpace($env:BOOTNEXA_CODESIGN_PFX_B64) -or
    [string]::IsNullOrWhiteSpace($env:BOOTNEXA_CODESIGN_PFX_PASSWORD) -or
    [string]::IsNullOrWhiteSpace($env:BOOTNEXA_CODESIGN_THUMBPRINT)) {
  throw 'Production release blocked: trusted code-signing credentials or expected thumbprint are not configured.'
}
. (Join-Path $PSScriptRoot 'Signing.Common.ps1')
$pfxPath = Join-Path $env:RUNNER_TEMP 'bootnexa-release.pfx'
try {
  $bytes = [Convert]::FromBase64String($env:BOOTNEXA_CODESIGN_PFX_B64)
  [System.IO.File]::WriteAllBytes($pfxPath, $bytes)
  $password = ConvertTo-SecureString -String $env:BOOTNEXA_CODESIGN_PFX_PASSWORD -AsPlainText -Force
  $cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation 'Cert:\CurrentUser\My' -Password $password -Exportable:$false
  if ($cert.Thumbprint -ne $env:BOOTNEXA_CODESIGN_THUMBPRINT) { throw 'Signing identity differs from pinned release thumbprint.' }
  $null = Assert-Certificate -Thumbprint $cert.Thumbprint -Production
  "BOOTNEXA_SIGNER_THUMBPRINT=$($cert.Thumbprint)" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
  Write-Host 'Trusted production signer imported into temporary user certificate store.'
} finally {
  if (Test-Path -LiteralPath $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
  Remove-Item Env:BOOTNEXA_CODESIGN_PFX_B64 -ErrorAction SilentlyContinue
  Remove-Item Env:BOOTNEXA_CODESIGN_PFX_PASSWORD -ErrorAction SilentlyContinue
}
