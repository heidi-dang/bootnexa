# Developer-only authenticated Windows named-pipe acceptance.
$ErrorActionPreference='Stop'
$broker=[System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../agent/target/release/bootnexa-readonly-broker.exe'))
if (-not (Test-Path -LiteralPath $broker)) {throw 'Developer read-only broker not built'}
function Run-Case([string]$Mode,[bool]$ExpectSuccess) {
  $out=Join-Path $env:RUNNER_TEMP ("bootnexa-pipe-"+[guid]::NewGuid().ToString('N')+".out")
  $err="$out.err"
  $process=Start-Process -FilePath $broker -ArgumentList '--serve-once' -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
  try {
    $pipe=$null
    for ($i=0;$i -lt 120;$i++) {
      Start-Sleep -Milliseconds 100
      if (Test-Path -LiteralPath $out) {
        $first=Get-Content -LiteralPath $out -TotalCount 1 -ErrorAction SilentlyContinue
        if ($first -and $first.StartsWith('\\.\pipe\bootnexa-ro-')) {$pipe=$first.Trim();break}
      }
      if ($process.HasExited){throw 'Broker failed to create secure pipe'}
    }
    if (-not $pipe){throw 'Broker did not publish an ephemeral local endpoint'}
    if ($pipe -notmatch '^\\\\\.\\pipe\\bootnexa-ro-[0-9a-f]{32}$') {
      throw 'Broker generated invalid pipe identifier'
    }
    $output= & $broker $Mode $pipe 2>&1
    $exit=$LASTEXITCODE
    if ($ExpectSuccess) {
      if ($exit -ne 0){throw "Authenticated read-only request failed: $output"}
      $value=($output | Out-String) | ConvertFrom-Json
      if (-not $value.readOnly -or $value.physicalWriteAuthorized -or
          -not $value.authenticatedWindowsPeer -or
          $value.request -ne 'read_only_safety_report') {
        throw 'Pipe broker returned an unsafe response'
      }
    } else {
      if ($exit -eq 0) {throw "Forbidden $Mode request was accepted"}
    }
    $process.WaitForExit(30000) | Out-Null
    $process.Refresh()
    if (-not $process.HasExited){throw 'Broker remained active after one request'}
    if ($ExpectSuccess -and $process.ExitCode -ne 0) {
      throw 'Broker denied an authenticated read-only request'
    }
    if (-not $ExpectSuccess -and $process.ExitCode -eq 0) {
      throw 'Broker failed open for an invalid request'
    }
    Write-Host "PASS: Windows native one-shot pipe $Mode; accepted=$ExpectSuccess"
  } finally {
    if (-not $process.HasExited){Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue}
    $process.Dispose()
    Remove-Item -LiteralPath $out,$err -Force -ErrorAction SilentlyContinue
  }
}
Run-Case '--client' $true
Run-Case '--client-invalid-op' $false
Run-Case '--client-bad-nonce' $false
Run-Case '--client-invalid-version' $false
$bad= & $broker --client '\\.\pipe\untrusted-other-service' 2>&1
if ($LASTEXITCODE -eq 0){throw 'Client accepted arbitrary named pipe'}
$bad= & $broker --write-disk 0 2>&1
if ($LASTEXITCODE -ne 2){throw 'Broker CLI accepted write operation'}
Write-Host 'PASS: read-only named pipe rejects every destructive request variant.'
