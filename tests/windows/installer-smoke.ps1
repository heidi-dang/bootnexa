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
Assert-SignedFile -Path $installer[0].FullName -Thumbprint $thumb -AllowUntrustedTest
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
  Assert-SignedFile -Path $binary -Thumbprint $thumb -AllowUntrustedTest
  Assert-SignedFile -Path $uninstall -Thumbprint $thumb -AllowUntrustedTest
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
