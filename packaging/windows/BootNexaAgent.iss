; BootNexa Agent per-user Windows installer.
; Source binaries come from a clean, locked Rust build. No elevation or raw disk writes.
#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef SignedPackage
  #define SignedPackage 0
#endif
#define ProductName "BootNexa Agent"

[Setup]
AppId={{300f9830-c8e3-4eba-b0b6-7a2f1b3b71f6}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher=BootNexa
AppPublisherURL=https://github.com/heidi-dang/bootnexa
AppSupportURL=https://github.com/heidi-dang/bootnexa/issues
AppUpdatesURL=https://github.com/heidi-dang/bootnexa/releases
DefaultDirName={localappdata}\Programs\BootNexa Agent
DefaultGroupName=BootNexa
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
UsePreviousAppDir=yes
UsePreviousTasks=yes
OutputDir={#SourcePath}\..\..\out\windows
OutputBaseFilename=BootNexa-Agent-{#AppVersion}-windows-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupIconFile={#SourcePath}\bootnexa.ico
UninstallDisplayIcon={app}\bootnexa.ico
CloseApplications=yes
RestartApplications=no
#if SignedPackage
SignTool=bootnexa
SignedUninstaller=yes
#else
SignedUninstaller=no
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start BootNexa Agent when I sign in"

[Files]
Source: "{#SourcePath}\..\..\agent\target\release\bootnexa-agent.exe"; DestDir: "{app}"; DestName: "bootnexa-agent.exe"; Flags: ignoreversion
Source: "{#SourcePath}\bootnexa.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\BootNexa Agent"; Filename: "{app}\bootnexa-agent.exe"; Comment: "Run the local read-only BootNexa agent"; IconFilename: "{app}\bootnexa.ico"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BootNexa Agent"; ValueData: """{app}\bootnexa-agent.exe"""; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\bootnexa-agent.exe"; Description: "Launch BootNexa Agent"; Flags: nowait postinstall skipifsilent
