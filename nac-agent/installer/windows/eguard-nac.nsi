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
Var CodeFromName
Var ExplicitCode

; Strict bare-name parser, mirrored by selfenroll.CodeFromInstallerName.
; StrCmp is case-insensitive; emit uppercase characters from the code alphabet.
; Scratch registers are only used during .onInit, after command-line parsing.
Function CodeFromInstallerName
  StrCpy $R0 $EXEFILE
  StrLen $R1 $R0
  IntCmp $R1 255 0 0 name_done
  StrCpy $R2 0
name_safe_loop:
  IntCmp $R2 $R1 name_safe_done
  StrCpy $R3 $R0 1 $R2
  StrCpy $R4 0
name_unsafe_loop:
  StrCpy $R5 '/\:*?$\"<>|$\r$\n$\t' 1 $R4
  StrCmp $R5 '' name_safe_next
  StrCmp $R3 $R5 name_done
  IntOp $R4 $R4 + 1
  Goto name_unsafe_loop
name_safe_next:
  IntOp $R2 $R2 + 1
  Goto name_safe_loop
name_safe_done:
  StrCpy $R2 $R0 4 -4
  StrCmp $R2 '.exe' 0 name_done
  IntOp $R1 $R1 - 4
  StrCpy $R0 $R0 $R1
  StrCpy $R2 $R0 1 -1
  StrCmp $R2 ')' 0 name_find_separator
  ; Require one or more decimal digits, then '('; strip at most one space.
  IntOp $R1 $R1 - 2
  StrCpy $R6 0
name_digits:
  IntCmp $R1 0 0 name_done
  StrCpy $R2 $R0 1 $R1
  StrCpy $R3 0
name_digit_check:
  StrCpy $R4 '0123456789' 1 $R3
  StrCmp $R4 '' name_digits_end
  StrCmp $R2 $R4 name_digit_found
  IntOp $R3 $R3 + 1
  Goto name_digit_check
name_digit_found:
  IntOp $R6 $R6 + 1
  IntOp $R1 $R1 - 1
  Goto name_digits
name_digits_end:
  StrCmp $R6 0 name_done
  StrCmp $R2 '(' 0 name_done
  StrCpy $R0 $R0 $R1
  StrCpy $R2 $R0 1 -1
  StrCmp $R2 ' ' 0 name_find_separator
  IntOp $R1 $R1 - 1
  StrCpy $R0 $R0 $R1
name_find_separator:
  StrLen $R1 $R0
name_separator_loop:
  IntOp $R1 $R1 - 1
  IntCmp $R1 0 0 name_done
  StrCpy $R2 $R0 1 $R1
  StrCmp $R2 '_' name_candidate
  Goto name_separator_loop
name_candidate:
  IntOp $R1 $R1 + 1
  StrCpy $R0 $R0 '' $R1
  StrLen $R1 $R0
  StrCmp $R1 11 0 name_done
  StrCpy $R1 $R0 1 5
  StrCmp $R1 '-' 0 name_done
  StrCpy $R6 ''
  StrCpy $R1 0
name_code_loop:
  StrCmp $R1 11 name_accept
  StrCmp $R1 5 name_dash
  StrCpy $R2 $R0 1 $R1
  StrCpy $R3 0
name_alphabet_loop:
  StrCpy $R4 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' 1 $R3
  StrCmp $R4 '' name_done
  StrCmp $R2 $R4 name_letter
  IntOp $R3 $R3 + 1
  Goto name_alphabet_loop
name_dash:
  StrCpy $R4 '-'
name_letter:
  StrCpy $R6 '$R6$R4'
  IntOp $R1 $R1 + 1
  Goto name_code_loop
name_accept:
  StrCpy $Code $R6
  StrCpy $CodeFromName 1
name_done:
FunctionEnd

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "eGuard NAC Agent requires 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
  ${GetParameters} $R0
  ${GetOptions} $R0 "/BOOTSTRAP=" $Bootstrap
  ${GetOptions} $R0 "/ACTIVATION=" $Activation
  ClearErrors
  ${GetOptions} $R0 "/CODE=" $Code
  ${IfNot} ${Errors}
    StrCpy $ExplicitCode 1
  ${EndIf}
  ${If} $ExplicitCode != 1
  ${AndIf} $Bootstrap == ""
  ${AndIf} $Activation == ""
    Call CodeFromInstallerName
  ${EndIf}
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
    Abort
  ${EndIf}
  ${If} $Code != ""
  ${AndIf} $CodeFromName != 1
    Abort
  ${EndIf}
  nsDialogs::Create 1018
  Pop $0
  ${If} $CodeFromName == 1
    ${NSD_CreateLabel} 0 0 100% 36u "This installer is ready to connect this device. Click Install."
  ${Else}
    ${NSD_CreateLabel} 0 0 100% 36u "Enter the enrollment code from your eGuard administrator."
  ${EndIf}
  Pop $0
  ${NSD_CreateText} 0 44u 100% 14u "$Code"
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
