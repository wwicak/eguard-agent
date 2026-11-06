// eGuard-authored canonical antivirus test; GPL-2.0-or-later.
rule eguard_eicar_test_file {
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $eicar at 0 and filesize <= 128
}
