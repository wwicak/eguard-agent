
import "pe"
rule Andariel_GopherRAT
{
  meta:
        score = 75
      author = "WithSecure"
      description = "Detects GopherRAT samples"
  strings:
    $cmdName1 = "GetMACHashID"
    $cmdName2 = "startHeartbeat"
    $cmdName3 = "encodeTo949"
    $cmdName4 = "xorDecrypt"
    $cmdName5 = "StartShell"
    $cmdName6 = "getLogicalDrives"
    $cmdName7 = "sendSocksCommand"
    $xorKey = {357095A221F033AC}
  condition:
    pe.is_pe and (
        3 of ($cmdName*)
        or $xorKey
    )
}
