# BootNexa Windows VM smoke. Runs the compiled agent; NEVER grants native access or modifies disks.
param([string]$BinaryPath = '')
$ErrorActionPreference = 'Stop'
$binary = if ($BinaryPath) { $BinaryPath } else { Join-Path $PSScriptRoot '../../agent/target/release/bootnexa-agent.exe' }
$binary = [System.IO.Path]::GetFullPath($binary)
if (-not (Test-Path $binary)) { throw "Native Windows agent not found: $binary" }
$base = 'http://127.0.0.1:43627'
$expectedOrigin = 'http://127.0.0.1:5173'
$env:BOOTNEXA_ALLOWED_ORIGIN = $expectedOrigin

$agent = Start-Process -FilePath $binary -PassThru -WindowStyle Hidden
try {
  $ready = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 250
    try {
      $healthResponse = Invoke-WebRequest -Uri "$base/v1/health" -Headers @{ Origin = $expectedOrigin } -TimeoutSec 2
      if ($healthResponse.StatusCode -eq 200) { $ready = $true; break }
    } catch {
      if ($agent.HasExited) { throw "Agent exited unexpectedly with $($agent.ExitCode)" }
    }
  }
  if (-not $ready) { throw 'Windows agent did not open its loopback listener' }
  $health = $healthResponse.Content | ConvertFrom-Json
  if ($health.platform -ne 'windows' -or $health.protocolVersion -ne '0.2' -or -not $health.readOnly) {
    throw "Incorrect Windows agent identity or protocol: $($healthResponse.Content)"
  }

  $caps = Invoke-RestMethod -Uri "$base/v1/capabilities" -Headers @{ Origin = $expectedOrigin }
  if ($caps.diskWrite -or $caps.format -or $caps.partition -or -not $caps.deviceDiscovery) {
    throw 'Unsafe or incorrect capability advertisement'
  }

  function Assert-Status($Path, $Expected, $Method, $Origin) {
    $response = Invoke-WebRequest -Uri "$base$Path" -Method $Method -Headers @{ Origin = $Origin } -SkipHttpErrorCheck -TimeoutSec 5
    if ([int]$response.StatusCode -ne $Expected) {
      throw "$Method $Path expected $Expected, received $($response.StatusCode) : $($response.Content)"
    }
  }
  Assert-Status '/v1/devices' 401 GET $expectedOrigin
  Assert-Status '/v1/devices' 403 GET 'https://untrusted.example'
  Assert-Status '/v1/jobs' 404 POST $expectedOrigin
  Assert-Status '/v1/format' 404 POST $expectedOrigin
  Assert-Status '/v1/erase' 404 POST $expectedOrigin

  # Independent safety probe: no admin elevation, disk handles or write APIs.
  # The CLI accepts only --probe; snapshots are collected twice and compared.
  $probe = Join-Path (Split-Path -Parent $binary) 'bootnexa-safety-probe.exe'
  if (-not (Test-Path -LiteralPath $probe)) { throw 'Read-only safety probe binary was not built' }
  $probeResult = & $probe --probe
  if ($LASTEXITCODE -ne 0) { throw 'Read-only Windows safety probe failed closed' }
  $safety = ($probeResult | Out-String) | ConvertFrom-Json
  if (-not $safety.readOnly -or $safety.physicalWriteAuthorized -or $safety.snapshotCount -ne 2) {
    throw 'Windows safety probe advertised unsafe capabilities'
  }
  foreach ($finding in @($safety.findings)) {
    if ($finding.physicalWriteAuthorized -or -not $finding.diagnosticTag.StartsWith('diag-')) {
      throw 'Unsafe per-disk safety finding'
    }
    if ($finding.riskCodes -notcontains 'native_volume_extents_unverified') {
      throw 'Windows safety probe must retain native IOCTL volume-extent release gate'
    }
  }
  Write-Host "PASS: separate read-only Windows safety probe verified $(@($safety.findings).Count) disk finding(s), no write authority."
  Assert-Status '/v1/safety/probe' 404 GET $expectedOrigin
  Assert-Status '/v1/safety/authorize' 404 POST $expectedOrigin
  Assert-Status '/v1/disk/write' 404 POST $expectedOrigin

  # Genuine Windows Storage API read-only query; no USB fixture/device writes.
  $disks = @(Get-Disk -ErrorAction Stop)
  Write-Host "Actual Windows Get-Disk succeeded (inventory entries: $($disks.Count)); no write operation."
  Write-Host 'PASS: Windows agent executable, loopback, API capabilities, auth rejection, no write routes.'
}
finally {
  if ($agent -and -not $agent.HasExited) {
    Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item Env:BOOTNEXA_ALLOWED_ORIGIN -ErrorAction SilentlyContinue
}
