/// Number of features in the model's input vector.
pub const FEATURE_COUNT: usize = 19;

/// Feature names for interpretability / logging.
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "z1_ioc_hit",
    "z2_temporal_count",
    "z3_anomaly_high",
    "z3_anomaly_med",
    "z4_killchain_count",
    "yara_hit_count",
    "string_sig_count",
    "event_class_risk",
    "uid_is_root",
    "dst_port_risk",
    "has_command_line",
    "cmdline_length_norm",
    "prefilter_hit",
    "multi_layer_count",
    // Information-theoretic features (Layer 5 exclusive)
    "cmdline_renyi_h2",    // Collision entropy — detects repeated patterns
    "cmdline_compression", // Kolmogorov complexity proxy — detects encryption/packing
    "cmdline_min_entropy", // Min-entropy — detects deterministic components
    "cmdline_entropy_gap", // H₁ - H_∞ gap — flat = random/encrypted, steep = structured
    "dns_entropy",         // Shannon entropy of domain label (DGA/tunneling signal)
];
