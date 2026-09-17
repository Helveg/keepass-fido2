; Inno Setup script for KeePass FIDO2: the plugin goes into the Plugins folder of a detected (or
; chosen) KeePass, kp.exe and kp-run into the application folder, optionally added to PATH.
;
; Built by scripts/package.ps1 -Installer:
;   ISCC /DAppVersion=0.1.0 /DDistDir=..\dist /DRepoDir=.. keepass-fido2.iss
;
; Silent install into a specific KeePass:
;   keepass-fido2-<version>-setup.exe /VERYSILENT /KEEPASSDIR="C:\Tools\KeePass"

#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef DistDir
  #define DistDir "..\dist"
#endif
#ifndef RepoDir
  #define RepoDir ".."
#endif

[Setup]
; Identifies this product for upgrades and uninstall; never change it.
AppId={{69F7606B-66C7-4456-9A1A-1C32B836BD63}
AppName=KeePass FIDO2
AppVersion={#AppVersion}
AppVerName=KeePass FIDO2 {#AppVersion}
AppPublisher=Robin De Schepper
AppPublisherURL=https://github.com/Helveg/keepass-fido2
AppSupportURL=https://github.com/Helveg/keepass-fido2/issues
DefaultDirName={autopf}\KeePass FIDO2
DisableProgramGroupPage=yes
LicenseFile={#RepoDir}\LICENSE
OutputDir={#DistDir}
OutputBaseFilename=keepass-fido2-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible or x86compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ChangesEnvironment=yes
; Asks to close KeePass when an update replaces the plugin it has loaded.
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=KeePass FIDO2
MinVersion=10.0

[Types]
Name: "full"; Description: "Plugin and kp command-line tool"
Name: "plugin"; Description: "Plugin only"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "plugin"; Description: "KeePass plugin: unlock with Windows Hello and FIDO2 security keys"; Types: full plugin custom
Name: "kp"; Description: "kp: KeePass values for .env files and commands"; Types: full custom

[Tasks]
Name: "addtopath"; Description: "Add kp to the PATH"; Components: kp

[Files]
Source: "{#DistDir}\KeePassFido2.dll"; DestDir: "{code:KeePassPluginDir}"; Components: plugin; Flags: ignoreversion
Source: "{#DistDir}\kp.exe"; DestDir: "{app}"; Components: kp; Flags: ignoreversion
Source: "{#DistDir}\kp-run"; DestDir: "{app}"; Components: kp; Flags: ignoreversion
Source: "{#RepoDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Messages]
FinishedLabel=Setup has installed KeePass FIDO2.%n%nRestart KeePass if it is running, open a database and use Tools > KeePass FIDO2 > Manage unlock methods.

[Code]
const
  KeePassUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1';
  MachineEnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  UserEnvironmentKey = 'Environment';

var
  KeePassPage: TInputDirWizardPage;

function ReadKeePassLocation(RootKey: Integer; var Dir: String): Boolean;
begin
  Result := RegQueryStringValue(RootKey, KeePassUninstallKey, 'InstallLocation', Dir)
    and FileExists(AddBackslash(Dir) + 'KeePass.exe');
end;

function DetectKeePassDir(): String;
var
  Dir: String;
begin
  Result := ExpandConstant('{param:KEEPASSDIR}');
  if Result <> '' then
    Exit;
  if IsWin64 and ReadKeePassLocation(HKLM64, Dir) then
    Result := Dir
  else if ReadKeePassLocation(HKLM32, Dir) then
    Result := Dir
  else if ReadKeePassLocation(HKCU, Dir) then
    Result := Dir
  else if FileExists(ExpandConstant('{commonpf}\KeePass Password Safe 2\KeePass.exe')) then
    Result := ExpandConstant('{commonpf}\KeePass Password Safe 2');
  Result := RemoveBackslashUnlessRoot(Result);
end;

procedure InitializeWizard();
begin
  KeePassPage := CreateInputDirPage(wpSelectComponents,
    'KeePass location', 'Where is KeePass installed?',
    'The plugin is copied into the Plugins folder next to KeePass.exe. Pick the folder of a portable KeePass if you use one.',
    False, '');
  KeePassPage.Add('');
  KeePassPage.Values[0] := DetectKeePassDir();
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = KeePassPage.ID) and not WizardIsComponentSelected('plugin');
end;

function KeePassPluginDir(Param: String): String;
begin
  Result := AddBackslash(KeePassPage.Values[0]) + 'Plugins';
end;

{ Checks the chosen KeePass folder; returns an error message, or '' when it can be used. }
function KeePassDirProblem(): String;
var
  Dir, Probe: String;
begin
  Result := '';
  if not WizardIsComponentSelected('plugin') then
    Exit;
  Dir := KeePassPage.Values[0];
  if (Dir = '') or not FileExists(AddBackslash(Dir) + 'KeePass.exe') then
  begin
    Result := 'KeePass.exe was not found in "' + Dir + '". Choose the folder that contains KeePass.exe.';
    Exit;
  end;
  { A per-user install cannot write into Program Files. }
  ForceDirectories(KeePassPluginDir(''));
  Probe := AddBackslash(KeePassPluginDir('')) + 'keepass-fido2-setup.tmp';
  if not SaveStringToFile(Probe, '', False) then
    Result := 'Setup cannot write to "' + KeePassPluginDir('') + '". Install for all users (as administrator), or choose a KeePass in a folder you can write to.'
  else
    DeleteFile(Probe);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Problem: String;
begin
  Result := True;
  if CurPageID = KeePassPage.ID then
  begin
    Problem := KeePassDirProblem();
    if Problem <> '' then
    begin
      MsgBox(Problem, mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Silent installs skip NextButtonClick, so check again here. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := KeePassDirProblem();
end;

function EnvironmentRoot(): Integer;
begin
  if IsAdminInstallMode then
    Result := HKLM
  else
    Result := HKCU;
end;

function EnvironmentKey(): String;
begin
  if IsAdminInstallMode then
    Result := MachineEnvironmentKey
  else
    Result := UserEnvironmentKey;
end;

procedure AddToPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(EnvironmentRoot(), EnvironmentKey(), 'Path', Paths) then
    Paths := '';
  if Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    Exit;
  if (Paths <> '') and (Paths[Length(Paths)] <> ';') then
    Paths := Paths + ';';
  RegWriteExpandStringValue(EnvironmentRoot(), EnvironmentKey(), 'Path', Paths + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvironmentRoot(), EnvironmentKey(), 'Path', Paths) then
    Exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then
    Exit;
  Delete(Paths, P, Length(Dir) + 1);
  RegWriteExpandStringValue(EnvironmentRoot(), EnvironmentKey(), 'Path', Copy(Paths, 2, Length(Paths) - 2));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
