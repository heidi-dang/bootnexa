param(
  [Parameter(Mandatory)][string]$Path,
  [Parameter(Mandatory)][string]$Thumbprint,
  [ValidateSet('Test','Production')][string]$Mode = 'Test',
  [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
. (Join-Path $PSScriptRoot 'Signing.Common.ps1')
$production = $Mode -eq 'Production'
$null = Assert-Certificate -Thumbprint $Thumbprint -Production:$production
$signTool = Find-SignTool
$full = (Resolve-Path -LiteralPath $Path).Path
$args = @('sign','/fd','SHA256','/sha1',$Thumbprint)
if ($production) {
  if ($TimestampUrl -notmatch '^https?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/.*)?$') { throw 'Invalid timestamp URL.' }
  $args += @('/tr',$TimestampUrl,'/td','SHA256')
}
$args += $full
& $signTool @args
if ($LASTEXITCODE -ne 0) { throw "Code signing failed: $full" }
Assert-SignedFile -Path $full -Thumbprint $Thumbprint -RequireTimestamp:$production -AllowUntrustedTest:(!$production)
Write-Host "Verified Authenticode ($Mode): $(Split-Path -Leaf $full)"
