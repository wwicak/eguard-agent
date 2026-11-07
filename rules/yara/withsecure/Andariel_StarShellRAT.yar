
import "pe"
rule Andariel_StarShellRAT
{
  meta:
        score = 75
      author = "WithSecure"
      description = "Detects StarshellRAT samples"
  strings:
    $str1 = "StarShell" ascii
    $str2 = "ReadRlt" ascii
    $str3 = "SendRlt" ascii
    $str4 = "ProcessShell" ascii
    $str5 = "Screan ok" wide
    $str6 = "<==>" wide
    $str7 = "\\r\\nStarted..." wide
    $str8 = "\\r\\nDownload End." wide
    $str9 = "\\r\\nupload end" wide
  condition:
    pe.is_pe and 3 of them
}
