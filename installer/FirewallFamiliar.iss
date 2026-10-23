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

[Files]
Source: "..\publish\FirewallFamiliar\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Firewall Familiar"; Filename: "{app}\FirewallFamiliar.exe"
Name: "{autodesktop}\Firewall Familiar"; Filename: "{app}\FirewallFamiliar.exe"; Tasks: desktopicon

[Registry]
; El icono junto al reloj, para todos los usuarios (no necesita ser administrador)
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "FirewallFamiliar"; ValueData: """{app}\FirewallFamiliar.exe"" --icono"; Flags: uninsdeletevalue

[Run]
; El servicio de Windows hace el bloqueo desde que arranca el PC (y vuelve a poner el icono a cada usuario)
Filename: "{app}\FirewallFamiliar.exe"; Parameters: "--instalar-servicio"; Flags: runhidden waituntilterminated; StatusMsg: "Activando la protección..."
Filename: "{app}\FirewallFamiliar.exe"; Description: "Abrir Firewall Familiar ahora"; Flags: postinstall nowait skipifsilent runascurrentuser

[UninstallRun]
Filename: "{app}\FirewallFamiliar.exe"; Parameters: "--quitar-servicio"; Flags: runhidden waituntilterminated; RunOnceId: "QuitarServicio"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM FirewallFamiliar.exe"; Flags: runhidden; RunOnceId: "Cerrar"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Firewall Familiar"" /F"; Flags: runhidden; RunOnceId: "QuitarArranque"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { Parar el servicio y cerrar las copias abiertas (ventana e iconos) para poder sustituir los archivos }
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop FirewallFamiliar', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(2000);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM FirewallFamiliar.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(1000);
  Result := '';
end;
