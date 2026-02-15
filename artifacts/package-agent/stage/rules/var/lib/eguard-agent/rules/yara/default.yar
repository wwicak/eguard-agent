rule eguard_default_marker_rule {
  strings:
    $marker = "eguard-malware-test-marker"
  condition:
    $marker
}
