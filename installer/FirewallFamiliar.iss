; Instalador de Firewall Familiar (Inno Setup 6)
; Se compila en GitHub Actions:  iscc /DMyVersion=0.5.0 installer\FirewallFamiliar.iss

#ifndef MyVersion
  #define MyVersion "0.0.0"
#endif

[Setup]
AppId={{6F3A3C0E-6A1B-4B8E-9A52-6A1F0C7A2B11}
AppName=Firewall Familiar
AppVersion={#MyVersion}
AppVerName=Firewall Familiar {#MyVersion}
AppPublisher=Firewall Familiar
DefaultDirName={autopf}\Firewall Familiar
DefaultGroupName=Firewall Familiar
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\publish
OutputBaseFilename=FirewallFamiliar-Instalar
SetupIconFile=..\src\FirewallFamiliar\Assets\FirewallFamiliar.ico
UninstallDisplayIcon={app}\FirewallFamiliar.exe
UninstallDisplayName=Firewall Familiar
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el Escritorio"; GroupDescription: "Accesos directos:"
Name: "autostart"; Description: "Abrir Firewall Familiar al iniciar sesión (recomendado)"; GroupDescription: "Arranque:"

[Files]
Source: "..\publish\FirewallFamiliar\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Firewall Familiar"; Filename: "{app}\FirewallFamiliar.exe"
Name: "{autodesktop}\Firewall Familiar"; Filename: "{app}\FirewallFamiliar.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\FirewallFamiliar.exe"; Parameters: "--registrar-arranque"; Flags: runhidden waituntilterminated; Tasks: autostart
; Instalación normal: casilla "Abrir ahora". Actualización automática (silenciosa): se vuelve a abrir sola junto al reloj.
Filename: "{app}\FirewallFamiliar.exe"; Description: "Abrir Firewall Familiar ahora"; Flags: postinstall nowait skipifsilent runascurrentuser
Filename: "{app}\FirewallFamiliar.exe"; Parameters: "--bandeja"; Flags: nowait; Check: WizardSilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM FirewallFamiliar.exe"; Flags: runhidden; RunOnceId: "Cerrar"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Firewall Familiar"" /F"; Flags: runhidden; RunOnceId: "QuitarArranque"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { Cerrar la copia que esté abierta para poder sustituir los archivos }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FirewallFamiliar.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(1000);
  Result := '';
end;
