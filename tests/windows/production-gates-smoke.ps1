# Prove that CI test signatures cannot cross the production publishing boundary.
# A test-only signer must never be accepted as a production certificate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:CI -or -not $env:GITHUB_ACTIONS) { throw 'Only run on disposable GitHub CI.' }
if (-not $env:BOOTNEXA_SIGNER_THUMBPRINT) { throw 'Missing ephemeral CI certificate.' }
. (Join-Path $PSScriptRoot '../../scripts/windows/Signing.Common.ps1')
$thumb = $env:BOOTNEXA_SIGNER_THUMBPRINT

$rejectedCert = $false
try {
  $null = Assert-Certificate -Thumbprint $thumb -Production
} catch {
  $rejectedCert = $true
  Write-Host 'PASS: CI-only signing certificate rejected by production policy.'
}
if (-not $rejectedCert) { throw 'CRITICAL: CI certificate accepted as publicly trusted.' }

$installers = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../out/windows') -Filter '*-Setup.exe')
if ($installers.Count -ne 1) { throw 'Expected one CI-signed test installer.' }
$rejectedArtifact = $false
try {
  Assert-SignedFile -Path $installers[0].FullName -Thumbprint $thumb -RequireTimestamp
} catch {
  $rejectedArtifact = $true
  Write-Host 'PASS: unsigned-trust test installer cannot pass production Authenticode checks.'
}
if (-not $rejectedArtifact) { throw 'CRITICAL: test installer accepted as production signature.' }

# Release cert import fails without required production secrets: do not create an
# unsigned-fallback path or expose fake credentials on CI.
$previousB64 = $env:BOOTNEXA_CODESIGN_PFX_B64
$previousPassword = $env:BOOTNEXA_CODESIGN_PFX_PASSWORD
$previousThumbprint = $env:BOOTNEXA_CODESIGN_THUMBPRINT
try {
  Remove-Item Env:BOOTNEXA_CODESIGN_PFX_B64 -ErrorAction SilentlyContinue
  Remove-Item Env:BOOTNEXA_CODESIGN_PFX_PASSWORD -ErrorAction SilentlyContinue
  Remove-Item Env:BOOTNEXA_CODESIGN_THUMBPRINT -ErrorAction SilentlyContinue
  $rejectedMissingSecrets = $false
  try {
    & (Join-Path $PSScriptRoot '../../scripts/windows/Import-ReleaseCertificate.ps1')
  } catch {
    $rejectedMissingSecrets = $true
    Write-Host 'PASS: production signing refuses missing certificate secrets and identity pin.'
  }
  if (-not $rejectedMissingSecrets) { throw 'CRITICAL: release importer accepted missing secrets.' }
} finally {
  if ($null -ne $previousB64) { $env:BOOTNEXA_CODESIGN_PFX_B64 = $previousB64 }
  if ($null -ne $previousPassword) { $env:BOOTNEXA_CODESIGN_PFX_PASSWORD = $previousPassword }
  if ($null -ne $previousThumbprint) { $env:BOOTNEXA_CODESIGN_THUMBPRINT = $previousThumbprint }
}
Write-Host 'PASS: all production signing negative gates hold.'
