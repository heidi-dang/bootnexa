param(
  [Parameter(Mandatory)][string]$Thumbprint,
  [ValidateSet('Test','Production')][string]$Mode = 'Test',
  [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
. (Join-Path $PSScriptRoot 'Signing.Common.ps1')
$production = $Mode -eq 'Production'
$null = Assert-Certificate -Thumbprint $Thumbprint -Production:$production
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$manifest = Get-Content -Raw -LiteralPath (Join-Path $root 'agent/Cargo.toml')
if ($manifest -notmatch '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') { throw 'Cannot locate agent version.' }
$version = $Matches[1]
$agent = Join-Path $root 'agent/target/release/bootnexa-agent.exe'
if (-not (Test-Path -LiteralPath $agent)) { throw 'Build the locked Rust release agent first.' }
$signTool = Find-SignTool
$iscc = Find-Iscc
& (Join-Path $PSScriptRoot 'Sign-Artifact.ps1') -Path $agent -Thumbprint $Thumbprint -Mode $Mode -TimestampUrl $TimestampUrl
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'Agent signing failed.' }
$stampArgs = if ($production) { "/tr $TimestampUrl /td SHA256 " } else { '' }
# Inno Setup invokes this SignTool for BOTH setup and its embedded uninstaller.
# $f is an Inno Setup placeholder resolved to a quoted output path.
# Inno Setup 6 parses command-line sign tools itself; nested quoted
# Program Files SDK paths otherwise split /S into stray script arguments.
# Stage SignTool in a whitespace-free, ignored build directory.
$signToolForInno = Join-Path $root 'out/windows/signtool-package.exe'
New-Item -ItemType Directory -Force -Path (Split-Path $signToolForInno -Parent) | Out-Null
Copy-Item -LiteralPath $signTool -Destination $signToolForInno -Force
$signCommand = "$signToolForInno sign /fd SHA256 /sha1 $Thumbprint $stampArgs" + '$f'
$installerScript = Join-Path $root 'packaging/windows/BootNexaAgent.iss'
try {
  & $iscc "/DAppVersion=$version" '/DSignedPackage=1' "/Sbootnexa=$signCommand" $installerScript
  if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compiler/signing failed.' }
} finally {
  Remove-Item -LiteralPath $signToolForInno -Force -ErrorAction SilentlyContinue
}
$installer = Join-Path $root "out/windows/BootNexa-Agent-$version-windows-x64-Setup.exe"
if (-not (Test-Path -LiteralPath $installer)) { throw 'Installer output missing.' }
Assert-SignedFile -Path $installer -Thumbprint $Thumbprint -RequireTimestamp:$production -AllowUntrustedTest:(!$production)
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()
Write-Host "SIGNED INSTALLER SHA256: $sha"
Write-Host "Installer path: $installer"
