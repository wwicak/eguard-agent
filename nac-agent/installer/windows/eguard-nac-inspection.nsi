Unicode True
Name "eGuard NAC TEST-UNSIGNED (NOT INSTALLABLE)"
OutFile "../../dist/eGuard-NAC-Setup-0.1.0-x64-TEST-UNSIGNED.exe"
RequestExecutionLevel user
SilentInstall normal
Page instfiles
Section "Inspection only"
  DetailPrint "TEST-UNSIGNED inspection package. No service, persistence or enrollment is installed."
  DetailPrint "Device credential, signed server lifecycle, ACL and recovery are not implemented."
  SetOutPath "$TEMP\eguard-nac-inspection"
  File "../../dist/eguard-nac-service-TEST-UNSIGNED.exe"
  DetailPrint "Payload copied to temporary inspection directory only; delete it when done."
SectionEnd
