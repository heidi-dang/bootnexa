# Adversarial read-only broker: independent Windows user + low IL + deadlines
$ErrorActionPreference = 'Stop'
$broker=[System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../agent/target/release/bootnexa-readonly-broker.exe'))
if(-not(Test-Path $broker)){throw 'Read-only IPC broker missing'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BootNexaPipeAdversary {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool LogonUserW(string name,string domain,string password,int logonType,int provider,out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr current,uint access,IntPtr attributes,int level,int type,out IntPtr duplicate);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSidToSidW(string text,out IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetLengthSid(IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int infoClass,ref TokenMandatoryLabel label,uint size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LocalFree(IntPtr handle);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes {public IntPtr sid;public uint attrs;}
  [StructLayout(LayoutKind.Sequential)] struct TokenMandatoryLabel {public SidAndAttributes label;}
  const uint ReadWrite=0xC0000000;
  static int TryOpen(string pipe) {
    IntPtr h=CreateFileW(pipe,ReadWrite,0,IntPtr.Zero,3,0,IntPtr.Zero);
    if (h==new IntPtr(-1)) return Marshal.GetLastWin32Error();
    CloseHandle(h);
    return 0;
  }
  public static int OtherUser(string domain,string user,string password,string pipe) {
    if (!LogonUserW(user,domain,password,3,0,out var token)) throw new Exception("Unable to create different-user Windows logon token: "+Marshal.GetLastWin32Error());
    try {
      if (!ImpersonateLoggedOnUser(token)) throw new Exception("Cannot impersonate different-user token: "+Marshal.GetLastWin32Error());
      try {return TryOpen(pipe);}
      finally {if(!RevertToSelf()) Environment.FailFast("Windows thread impersonation could not be reverted");}
    } finally {CloseHandle(token);}
  }
  public static int LowIntegrity(string pipe) {
    if(!OpenProcessToken(GetCurrentProcess(),0x0002|0x0008,out var current)) throw new Exception("OpenProcessToken: "+Marshal.GetLastWin32Error());
    try {
      if(!DuplicateTokenEx(current,0x0008|0x0002|0x0004|0x0080,IntPtr.Zero,2,2,out var token)) throw new Exception("DuplicateTokenEx: "+Marshal.GetLastWin32Error());
      try {
        if(!ConvertStringSidToSidW("S-1-16-4096",out var sid)) throw new Exception("ConvertStringSidToSid: "+Marshal.GetLastWin32Error());
        try {
          var label=new TokenMandatoryLabel{label=new SidAndAttributes{sid=sid,attrs=0x20}};
          uint size=(uint)Marshal.SizeOf(typeof(TokenMandatoryLabel))+GetLengthSid(sid);
          if(!SetTokenInformation(token,25,ref label,size)) throw new Exception("SetTokenInformation(low integrity): "+Marshal.GetLastWin32Error());
          if(!ImpersonateLoggedOnUser(token)) throw new Exception("Impersonate(low): "+Marshal.GetLastWin32Error());
          try {return TryOpen(pipe);}
          finally {if(!RevertToSelf()) Environment.FailFast("Windows thread impersonation could not be reverted");}
        } finally {LocalFree(sid);}
      } finally {CloseHandle(token);}
    } finally {CloseHandle(current);}
  }
}

'@
function New-TestBroker([int]$DeadlineMs) {
  $file=Join-Path $env:RUNNER_TEMP ("bootnexa-adversary-"+[guid]::NewGuid().ToString('N')+'.out')
  $errorFile="$file.err"
  $args= if($DeadlineMs -eq 0){@('--serve-once')}else{@('--serve-once-deadline-ms',"$DeadlineMs")}
  $p=Start-Process -FilePath $broker -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $file -RedirectStandardError $errorFile
  $pipe=$null
  for($i=0;$i -lt 100;$i++){
    Start-Sleep -Milliseconds 80
    $first=Get-Content $file -TotalCount 1 -ErrorAction SilentlyContinue
    if($first -and $first.StartsWith('\\.\pipe\bootnexa-ro-')){$pipe=$first.Trim();break}
    if($p.HasExited){throw "Broker exited while creating endpoint: $($p.ExitCode)"}
  }
  if(!$pipe){Stop-Process $p.Id -Force;throw 'Timed out opening broker pipe'}
  return @{Process=$p;Pipe=$pipe;Out=$file;Err=$errorFile}
}
function Close-TestBroker($test){
  if(!$test){return}
  if(!$test.Process.HasExited){Stop-Process -Id $test.Process.Id -Force -ErrorAction SilentlyContinue}
  $test.Process.Dispose()
  Remove-Item $test.Out,$test.Err -Force -ErrorAction SilentlyContinue
}
$guestName='bnci'+([guid]::NewGuid().ToString('N').Substring(0,12))
$plainPassword=[guid]::NewGuid().ToString('N')+'aA1!'
$guestAdded=$false
$case=$null
try {
  $secure=ConvertTo-SecureString $plainPassword -AsPlainText -Force
  New-LocalUser -Name $guestName -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
  $guestAdded=$true
  $case=New-TestBroker 0
  $guestResult=[BootNexaPipeAdversary]::OtherUser($env:COMPUTERNAME,$guestName,$plainPassword,$case.Pipe)
  if($guestResult -ne 5){throw "Cross-user access must return Win32 ACCESS_DENIED (5); got $guestResult"}
  Write-Host 'PASS: distinct Windows user token denied by real named-pipe DACL'
  $lowResult=[BootNexaPipeAdversary]::LowIntegrity($case.Pipe)
  if($lowResult -ne 5){throw "Low-integrity access must return Win32 ACCESS_DENIED (5); got $lowResult"}
  Write-Host 'PASS: low-integrity impersonated caller denied writable local pipe'
  $good = & $broker --client $case.Pipe 2>&1
  if($LASTEXITCODE -ne 0){throw "Legitimate client failed after adversarial requests: $good"}
  if(-not $case.Process.WaitForExit(12000) -or $case.Process.ExitCode -ne 0) {throw 'Legitimate server did not exit normally after adversarial probes'}
  Close-TestBroker $case
  $case=$null
} finally {
  Close-TestBroker $case
  if($guestAdded){Remove-LocalUser -Name $guestName -ErrorAction Stop}
}
foreach($mode in @('no-client','--client-stall','--client-partial')){
  $case=$null
  $staller=$null
  try{
    $case=New-TestBroker 1500
    if($mode -ne 'no-client'){
      $staller=Start-Process -FilePath $broker -ArgumentList @($mode,$case.Pipe) -PassThru -WindowStyle Hidden
    }
    if(-not $case.Process.WaitForExit(8000)) {throw "Unbounded server wait for $mode"}
    if($case.Process.ExitCode -ne 124){throw "Deadline must fail closed with 124 for $mode; got $($case.Process.ExitCode)"}
    Write-Host "PASS: stalled IPC $mode bounded by process deadline"
  } finally {
    if($staller){
      if(-not $staller.HasExited){Stop-Process $staller.Id -Force -ErrorAction SilentlyContinue}
      $staller.Dispose()
    }
    Close-TestBroker $case
  }
}
$global:LASTEXITCODE=0
