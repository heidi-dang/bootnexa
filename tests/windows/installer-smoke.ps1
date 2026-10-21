param([switch]$Production)
# Destructive scope is restricted to a per-user CI test installation directory.
# Never runs if launched outside GitHub's disposable Windows VM.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:CI -or -not $env:GITHUB_ACTIONS) { throw 'Installer acceptance must run in disposable CI.' }
if (-not $env:BOOTNEXA_SIGNER_THUMBPRINT) { throw 'Missing CI signature identity.' }
. (Join-Path $PSScriptRoot '../../scripts/windows/Signing.Common.ps1')
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$installer = @(Get-ChildItem -LiteralPath (Join-Path $root 'out/windows') -Filter 'BootNexa-Agent-*-windows-x64-Setup.exe')
if ($installer.Count -ne 1) { throw 'Exactly one installer is required for smoke acceptance.' }
$thumb = $env:BOOTNEXA_SIGNER_THUMBPRINT
$signaturePolicy = @{ Thumbprint = $thumb; RequireTimestamp = [bool]$Production; AllowUntrustedTest = ![bool]$Production }
Assert-SignedFile -Path $installer[0].FullName @signaturePolicy
$installed = Join-Path $env:LOCALAPPDATA 'Programs/BootNexa Agent'
if (Test-Path -LiteralPath $installed) { throw 'Unexpected pre-existing BootNexa installation on runner.' }
$startup = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Get-ItemProperty -LiteralPath $startup -Name 'BootNexa Agent' -ErrorAction SilentlyContinue) {
  throw 'Unexpected pre-existing BootNexa startup entry.'
}
$installedSuccessfully = $false
try {
  $setup = Start-Process -FilePath $installer[0].FullName -ArgumentList @(
    '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/TASKS=!autostart'
  ) -Wait -PassThru
  if ($setup.ExitCode -ne 0) { throw "Silent per-user installation failed: $($setup.ExitCode)" }
  $installedSuccessfully = $true
  $binary = Join-Path $installed 'bootnexa-agent.exe'
  $uninstall = Join-Path $installed 'unins000.exe'
  if (-not (Test-Path -LiteralPath $binary) -or -not (Test-Path -LiteralPath $uninstall)) { throw 'Expected installed files are absent.' }
  Assert-SignedFile -Path $binary @signaturePolicy
  # Windows VERSIONINFO must identify exactly the software being signed.
  $metadata = (Get-Item -LiteralPath $binary).VersionInfo
  $cargo = Get-Content -Raw -LiteralPath (Join-Path $root 'agent/Cargo.toml')
  if ($cargo -notmatch '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') { throw 'Cargo version missing.' }
  $version = $Matches[1]
  if ($metadata.ProductName -ne 'BootNexa Agent' -or
      $metadata.CompanyName -ne 'BootNexa' -or
      $metadata.OriginalFilename -ne 'bootnexa-agent.exe' -or
      $metadata.ProductVersion -notlike "$version*" -or
      $metadata.FileVersion -notlike "$version*") {
    throw "Invalid Windows product metadata: $($metadata | Format-List | Out-String)"
  }
  Write-Host "PASS: Windows executable VERSIONINFO matches BootNexa Agent $version."

  # Mutating executable code bytes must invalidate the Authenticode digest.
  $tampered = Join-Path $env:RUNNER_TEMP 'bootnexa-tampered-agent.exe'
  $data = [System.IO.File]::ReadAllBytes($binary)
  if ($data.Length -le 8192) { throw 'Agent binary unexpectedly small.' }
  $data[4096] = $data[4096] -bxor 1
  [System.IO.File]::WriteAllBytes($tampered, $data)
  $rejected = $false
  try {
    Assert-SignedFile -Path $tampered @signaturePolicy
  } catch {
    $rejected = $true
    Write-Host 'PASS: tampered executable signature rejected.'
  }
  if (-not $rejected) { throw 'Tampered agent unexpectedly passed signature verification.' }
  Assert-SignedFile -Path $uninstall @signaturePolicy
  $original = Join-Path $root 'agent/target/release/bootnexa-agent.exe'
  if ((Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -ne
      (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) { throw 'Installed agent checksum mismatch.' }
  if (Get-ItemProperty -LiteralPath $startup -Name 'BootNexa Agent' -ErrorAction SilentlyContinue) {
    throw 'Disabled autostart was unexpectedly installed.'
  }
  Write-Host 'PASS: signed installer, signed binary, signed uninstaller, per-user silent install, no autostart.'
  # Exercise installed binary via the existing Windows loopback smoke, not just the staging build.
  & (Join-Path $PSScriptRoot 'smoke.ps1') -BinaryPath $binary
} finally {
  if ($installedSuccessfully) {
    $uninstall = Join-Path $installed 'unins000.exe'
    if (Test-Path -LiteralPath $uninstall) {
      $un = Start-Process -FilePath $uninstall -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru
      if ($un.ExitCode -ne 0) { throw "Uninstall failed: $($un.ExitCode)" }
    }
  }
}
Start-Sleep -Milliseconds 650
if (Test-Path -LiteralPath (Join-Path $installed 'bootnexa-agent.exe')) { throw 'Agent binary retained after uninstall.' }
if (Get-ItemProperty -LiteralPath $startup -Name 'BootNexa Agent' -ErrorAction SilentlyContinue) { throw 'Autostart retained after uninstall.' }
Write-Host 'PASS: CI package lifecycle and uninstall clean-up.'
