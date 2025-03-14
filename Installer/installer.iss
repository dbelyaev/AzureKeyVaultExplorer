; -----------------------------------------------------------------------------
;
; Script for building an installer for Really Slick Screensavers
;
; -----------------------------------------------------------------------------

[ISPP]
#define AppName "Azure Key Vault Explorer"
#define AppShortName "Vault Explorer"
#define AppLowerName "vault-explorer"
#define AppPublisher "Equinor"
#define AppUrl "https://github.com/equinor/AzureKeyVaultExplorer"

#ifndef VERSION
  #define VERSION "0.0.0.0"
#endif

#pragma message "Detected Version: " + VERSION

[Setup]
ArchitecturesInstallIn64BitMode    = x64compatible
ArchitecturesAllowed               = x86 x64compatible

; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
AppId={{3e75f48f-e670-4def-818f-0d0e4cba3a2f}

AppName={#AppName}
AppVersion={#VERSION}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}
AppUpdatesURL={#AppUrl}
DefaultDirName={autopf64}\{#AppLowerName}
DefaultGroupName={#AppName}

Compression=lzma
SolidCompression=yes
WizardStyle=modern

; root source directory
SourceDir=.\..\Vault\Explorer\bin\Release

; output directory is relative to SourceDir
OutputDir=.\..\..\..\..\Installer

; output installer file name
OutputBaseFilename={#AppLowerName}-installer

UninstallDisplayIcon={app}\VaultExplorer.exe
UninstallDisplayName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "norwegian"; MessagesFile: "compiler:Languages\Norwegian.isl"

[Files]
Source: "VaultExplorer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "VaultExplorer.exe.config"; DestDir: "{app}"; Flags: ignoreversion
Source: "ClearClipboard.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "ClearClipboard.exe.config"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.ApplicationInsights.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Azure.KeyVault.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Azure.KeyVault.WebKey.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Azure.Management.KeyVault.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Rest.ClientRuntime.Azure.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Rest.ClientRuntime.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Vault.Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Vault.Library.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Microsoft.Vault.Library.dll.config"; DestDir: "{app}"; Flags: ignoreversion
Source: "Newtonsoft.Json.Bson.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "Newtonsoft.Json.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "ScintillaNET.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Buffers.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Diagnostics.DiagnosticSource.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Memory.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Net.Http.Formatting.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Numerics.Vectors.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Runtime.CompilerServices.Unsafe.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Threading.Tasks.Extensions.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "System.Web.Http.dll"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\VaultExplorer.exe"; WorkingDir: "{app}"
