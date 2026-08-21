; Inno Setup script for Infra Monitor — a signed, single-file per-user installer.
; Ships the tray/dashboard exe, an EMPTY starter machines.json (preserved on
; upgrade), a documented machines.example.json, docs and the QuickOpen Root CA.
; Compiled and Authenticode-signed in CI.
;
; Expects packaging\staging\ to hold: InfraMonitor.exe, machines.json,
; machines.example.json, Install-InfraMonitor.ps1, README.md, LICENSE,
; quickopen-root.crt.

#define AppName "Infra Monitor"
#define AppVersion "1.0.14"
#define AppPublisher "QuickOpen (quickopen.ai)"
#define AppURL "https://quickopen.ai/projects/infra-monitor"

[Setup]
AppMutex=QuickOpen.InfraMonitor
AppId={{7F2C6A81-3E94-4B15-9D62-8A0F1C2D3E40}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\InfraMonitor
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\InfraMonitor.exe
; unins000.exe ships UNSIGNED by default, and on a machine with Smart App
; Control or a WDAC policy enforcing, Windows refuses to load it: the Uninstall
; button in Settings fails with CodeIntegrity 3077/3033 and WinError 4551,
; leaving the app impossible to remove through the normal route.
;
; Inno writes that binary on the USER'S machine at install time from a template
; baked into the installer, so no later signing hop can reach it - COMPILE time
; is the only moment it can be signed, which is what SignedUninstaller=yes does.
; That needs a SignTool where ISCC runs, so the ISCC step moved onto the signing
; machine (2026-08-21). ISCC signs uninst.e32, then the setup exe.
;
; Guarded by #ifdef so this same .iss still compiles anywhere without the token
; (CI, a laptop) - just unsigned. publish/scripts/compile-windows-installer.sh
; passes /DSIGNED_UNINSTALLER and defines the "quickopen" SignTool.
#ifdef SIGNED_UNINSTALLER
SignTool=quickopen
SignedUninstaller=yes
#endif
OutputDir=dist
OutputBaseFilename=InfraMonitor-Setup
SetupIconFile=..\infra-monitor.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=branding\wizard-large.bmp
WizardSmallImageFile=branding\wizard-small.bmp
AppCopyright=Apache-2.0. 100%% AI-built, published on QuickOpen (quickopen.ai).
VersionInfoCompany=QuickOpen
VersionInfoProductName=Infra Monitor
VersionInfoVersion=1.0.14.0
; Per-user install (no admin). The app monitors over SSH from your account and
; keeps its config next to the exe, which stays writable this way.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=Infra Monitor is a 100%% AI-built, open-source desktop monitor for a fleet of Linux/SSH machines, published on QuickOpen (quickopen.ai).%n%nAfter installing, add your machines in machines.json (see machines.example.json).
BeveledLabel=QuickOpen · quickopen.ai

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "trustca"; Description: "Trust the QuickOpen Root CA (lets Windows verify QuickOpen signatures)"; GroupDescription: "Security:"; Flags: unchecked

[Files]
Source: "staging\InfraMonitor.exe"; DestDir: "{app}"; Flags: ignoreversion
; Ship the empty starter config only if the user has not created one yet — an
; upgrade must never overwrite a configured fleet.
Source: "staging\machines.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "staging\machines.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\Install-InfraMonitor.ps1"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\quickopen-root.crt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\Infra Monitor"; Filename: "{app}\InfraMonitor.exe"; IconFilename: "{app}\InfraMonitor.exe"
Name: "{group}\Edit machines.json"; Filename: "notepad.exe"; Parameters: """{app}\machines.json"""
Name: "{group}\Uninstall Infra Monitor"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Infra Monitor"; Filename: "{app}\InfraMonitor.exe"; IconFilename: "{app}\InfraMonitor.exe"; Tasks: desktopicon

[Run]
Filename: "certutil.exe"; Parameters: "-addstore -user Root ""{app}\quickopen-root.crt"""; Tasks: trustca; Flags: runhidden; StatusMsg: "Trusting the QuickOpen Root CA..."
Filename: "{app}\InfraMonitor.exe"; Description: "Launch Infra Monitor now"; Flags: nowait postinstall skipifsilent

; Clean uninstall: remove the runtime config/logs the app writes outside {app}.
[UninstallDelete]
; Infra Monitor keeps all state (machines.json, settings, logs) next to the
; exe, so removing the install dir removes every trace.
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{localappdata}\InfraMonitor"

