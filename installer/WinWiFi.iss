#define AppName "WinWiFi Security Auditor"
#define AppVersion "3.0.1"
#define AppPublisher "Nexus Tech"
#define AppExeName "WinWiFi.exe"

[Setup]
AppId={{A0E7F6A2-345C-43E7-AE05-51C1F2D9A32B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\WinWiFi Security Auditor
DefaultGroupName=WinWiFi Security Auditor
OutputDir=..\publish\installer
OutputBaseFilename=WinWiFi-Setup
SetupIconFile=..\WinWiFi.Desktop\Assets\WinWiFi.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
WizardStyle=modern

[Files]
; Package the self-contained output produced by scripts\publish-windows.ps1.
; Do not use bin\Release here: that build depends on a machine-wide .NET runtime.
Source: "..\publish\win-x64\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\WinWiFi Security Auditor"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\WinWiFi Security Auditor"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch WinWiFi Security Auditor"; Flags: nowait postinstall skipifsilent
