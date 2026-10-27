rule Virelith_Safe_Test_Marker {
  meta:
    description = "Test marker only; a match DOES NOT mean malware"
  strings:
    $marker = "VIRELITH_TEST_MARKER_2026" ascii
  condition:
    $marker
}
