# Utilities shared by Windows package/verification scripts.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-SignTool {
  $base = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
  $found = @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction Stop |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'x64/signtool.exe' } |
    Where-Object { Test-Path -LiteralPath $_ })
  if ($found.Count -eq 0) { throw 'Windows SDK SignTool.exe is required.' }
  return $found[0]
}
function Find-Iscc {
  foreach ($path in @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
  )) {
    if (Test-Path -LiteralPath $path) { return $path }
  }
  $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw 'Inno Setup 6 (ISCC.exe) not found.'
}
function Assert-Certificate {
  param([Parameter(Mandatory)][string]$Thumbprint, [switch]$Production)
  if ($Thumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid SHA-1 certificate thumbprint.' }
  $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
  if (-not $cert.HasPrivateKey) { throw 'Signing certificate has no private key.' }
  if ($cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -lt (Get-Date)) { throw 'Signing certificate is not valid now.' }
  $codeSigningEku = @($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })
  if ($codeSigningEku.Count -eq 0) { throw 'Expected a code-signing EKU.' }
  if ($Production) {
    if ($cert.Subject -match '(?i)(test|development|self.signed|ci only)') { throw 'Test certificate prohibited for production.' }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
      $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
      if (-not $chain.Build($cert)) {
        throw "Production certificate is not publicly trusted: $($chain.ChainStatus | Out-String)"
      }
    } finally { $chain.Dispose() }
  }
  return $cert
}
function Assert-SignedFile {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Thumbprint, [switch]$RequireTimestamp, [switch]$AllowUntrustedTest)
  $full = (Resolve-Path -LiteralPath $Path).Path
  $signature = Get-AuthenticodeSignature -LiteralPath $full
  if ($AllowUntrustedTest) {
    # Self-signed test certificates are deliberately NOT trusted by Windows.
    # Windows may report UnknownError (CERT_E_UNTRUSTEDROOT), not NotTrusted.
    # Only an explicit untrusted-chain message is acceptable, never a bad digest.
    $status = [string]$signature.Status
    $reason = [string]$signature.StatusMessage
    if ($status -notin @('Valid','NotTrusted') -and
        -not ($status -eq 'UnknownError' -and $reason -match '(?i)(untrusted root|not trusted by the trust provider|0x800b0109|certificate chain.*not trusted)')) {
      throw "CI Authenticode verification failed ($status): $full — $reason"
    }
    Write-Host "CI Authenticode status: $status ($reason)"
  } elseif ($signature.Status -ne 'Valid') { throw "Not a trusted Authenticode signature: $full — $($signature.Status)" }
  if ($signature.SignerCertificate.Thumbprint -ne $Thumbprint) { throw "Unexpected code-signing identity for $full" }
  if ($RequireTimestamp -and -not $signature.TimeStamperCertificate) { throw "No trusted timestamp: $full" }
  $signTool = Find-SignTool
  if (-not $AllowUntrustedTest) {
    & $signTool verify /pa /v $full
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed: $full" }
  }
}
