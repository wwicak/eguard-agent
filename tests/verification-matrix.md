# Verification Matrix

- unit_tests_target: 200
- ebpf_tests_target: 20
- detection_tests_target: 100
- response_tests_target: 30
- integration_tests_target: 50
- perl_api_tests_target: 40
- vue_component_tests_target: 20
- performance_benchmarks_target: 15
- stress_tests_target: 5

- incident_threshold_hosts: 3
- fleet_zscore_threshold: 3.0
- minhash_bands: 16
- minhash_rows: 8
- minhash_hashes: 128
- triage_weight_sum: 1.0

- threat_intel_poll_interval_hours: 4
- ioc_stale_threshold_days_min: 30
- ioc_stale_threshold_days_max: 90
