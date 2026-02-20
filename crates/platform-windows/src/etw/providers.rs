//! ETW provider GUID constants.
//!
//! Each constant represents a well-known Windows ETW provider used for
//! endpoint telemetry collection.

/// Microsoft-Windows-Kernel-Process provider.
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Microsoft-Windows-Kernel-File provider.
pub const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

/// Microsoft-Windows-Kernel-Network provider.
pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Microsoft-Windows-Kernel-Registry provider.
pub const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";

/// Microsoft-Windows-DNS-Client provider.
pub const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

/// Microsoft-Windows-Security-Auditing provider.
pub const SECURITY_AUDITING: &str = "54849625-5478-4994-A5BA-3E3B0328C30D";

/// Microsoft-Antimalware-Scan-Interface (AMSI) provider.
pub const AMSI_PROVIDER: &str = "2A576B87-09A7-520E-C21A-4942F0271D67";

/// Microsoft-Windows-WFP (Windows Filtering Platform) provider.
pub const WFP_PROVIDER: &str = "0C478C5B-0351-41B1-8C58-4A6737DA32E3";

/// Microsoft-Windows-ImageLoad provider for DLL/module load events.
pub const IMAGE_LOAD: &str = "2CB15D1D-5FC1-11D2-ABE1-00A0C911F518";
