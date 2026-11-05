; eGuard NAC Agent installer (not code-signed).
; Standard NSIS pages only: the enrollment/lifecycle UI mockup is pending approval,
; so no custom wizard UI is integrated. Enrollment material is supplied as files:
;
;   eGuard-NAC-Setup-<ver>-x64.exe /CODE=<enrollment code> [/S]        (self-service)
;   eGuard-NAC-Setup-<ver>-x64.exe /BOOTSTRAP=<path\bootstrap.json> /ACTIVATION=<path\activation.json> [/S]
;
; All verification (signature pin, binding, activation window), provisioning ACLs,
; service creation and readiness/rollback happen in nac-setup.exe (Go), not here.

Unicode True
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"
!include "nsDialogs.nsh"

!ifndef VERSION
  !define VERSION "0.2.0"
!endif
!ifndef PAYLOAD
  !define PAYLOAD "../../dist/payload"
!endif

Name "eGuard NAC Agent ${VERSION}"
OutFile "../../dist/eGuard-NAC-Setup-${VERSION}-x64.exe"
RequestExecutionLevel admin
ShowInstDetails show
InstallDir "$TEMP\eguard-nac-setup"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "eGuard NAC Agent"
VIAddVersionKey "FileDescription" "eGuard NAC Agent Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "eGuard"

Page license
Page custom CodePage CodePageLeave
Page instfiles
LicenseText "eGuard NAC Agent collects device posture for network access policy only." "I Agree"
LicenseData "${PAYLOAD}/NOTICE.txt"

Var Bootstrap
Var Activation
Var Code
Var CodeField

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "eGuard NAC Agent requires 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  ${GetParameters} $R0
  ${GetOptions} $R0 "/BOOTSTRAP=" $Bootstrap
  ${GetOptions} $R0 "/ACTIVATION=" $Activation
  ${GetOptions} $R0 "/CODE=" $Code
  ${If} $Bootstrap != ""
  ${OrIf} $Activation != ""
    ${If} $Bootstrap == ""
    ${OrIf} $Activation == ""
      MessageBox MB_ICONSTOP "Both /BOOTSTRAP= and /ACTIVATION= are required." /SD IDOK
      SetErrorLevel 2
      Abort
    ${EndIf}
    ${IfNot} ${FileExists} "$Bootstrap"
    ${OrIfNot} ${FileExists} "$Activation"
      MessageBox MB_ICONSTOP "Enrollment file not found." /SD IDOK
      SetErrorLevel 2
      Abort
    ${EndIf}
  ${ElseIf} $Code == ""
  ${AndIf} ${Silent}
    MessageBox MB_ICONSTOP "Usage: eGuard-NAC-Setup.exe /S /CODE=<enrollment code>" /SD IDOK
    SetErrorLevel 2
    Abort
  ${EndIf}
FunctionEnd

Function CodePage
  ${If} $Bootstrap != ""
  ${OrIf} $Code != ""
    Abort
  ${EndIf}
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 36u "Enter the enrollment code from your eGuard administrator (Access Control > NAC Agent > Enrollment & Install). Each code works once, for one device."
  Pop $0
  ${NSD_CreateText} 0 44u 100% 14u ""
  Pop $CodeField
  nsDialogs::Show
FunctionEnd

Function CodePageLeave
  ${NSD_GetText} $CodeField $Code
  ${If} $Code == ""
    MessageBox MB_ICONEXCLAMATION "Enter the enrollment code."
    Abort
  ${EndIf}
FunctionEnd

Section "Install"
  SetOutPath "$INSTDIR"
  File "${PAYLOAD}/eguard-nac-service.exe"
  File "${PAYLOAD}/nac-setup.exe"
  DetailPrint "Verifying enrollment, provisioning and starting the eGuard NAC service..."
  ${If} $Code != ""
    nsExec::ExecToLog '"$INSTDIR\nac-setup.exe" install-code "$INSTDIR\eguard-nac-service.exe" "$Code"'
  ${Else}
    nsExec::ExecToLog '"$INSTDIR\nac-setup.exe" install "$INSTDIR\eguard-nac-service.exe" "$Bootstrap" "$Activation"'
  ${EndIf}
  Pop $0
  ; Temporary extraction is always removed; nac-setup copied what it needed.
  SetOutPath "$TEMP"
  RMDir /r "$INSTDIR"
  ${If} $0 != 0
    DetailPrint "Installation failed (code $0). All changes were rolled back."
    MessageBox MB_ICONSTOP "eGuard NAC installation failed (code $0).$\r$\nNo changes were left on this device. See details for the reason." /SD IDOK
    SetErrorLevel $0
    Abort
  ${EndIf}
  DetailPrint "eGuard NAC Agent is installed and running."
SectionEnd
