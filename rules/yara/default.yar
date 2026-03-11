rule eguard_default_marker_rule {
  strings:
    $marker = "eguard-malware-test-marker"
  condition:
    $marker
}

rule eguard_eicar_test_file {
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar
}
